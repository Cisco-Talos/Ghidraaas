#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  GhIDA: Ghidraaas - Ghidra as a Service                                    #
#                                                                            #
#  Copyright 2019 Andrea Marcelli and Mariano Graziano, Cisco Talos          #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License");           #
#  you may not use this file except in compliance with the License.          #
#  You may obtain a copy of the License at                                   #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  Unless required by applicable law or agreed to in writing, software       #
#  distributed under the License is distributed on an "AS IS" BASIS,         #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#  See the License for the specific language governing permissions and       #
#  limitations under the License.                                            #
#                                                                            #
##############################################################################

import hashlib
import json
import os
import shutil
import subprocess
import traceback

from flask import Flask
from flask import request

from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import HTTPException

import coloredlogs
import logging
log = None

app = Flask(__name__)

# Load configuration
with open("config/config.json") as f_in:
    j = json.load(f_in)
    SAMPLES_DIR = j['SAMPLES_DIR']
    IDA_SAMPLES_DIR = j['IDA_SAMPLES_DIR']
    GHIDRA_SCRIPT = j['GHIDRA_SCRIPT']
    GHIDRA_OUTPUT = j['GHIDRA_OUTPUT']
    GHIDRA_PROJECT = j['GHIDRA_PROJECT']
    GHIDRA_PATH = j['GHIDRA_PATH']
    GHIDRA_HEADLESS = os.path.join(GHIDRA_PATH, "support/analyzeHeadless")


#############################################
#       UTILS                               #
#############################################

def set_logger(debug):
    """
    Set logger level and syntax
    """
    global log
    log = logging.getLogger('ghidraaas')
    if debug:
        loglevel = 'DEBUG'
    else:
        loglevel = 'INFO'
    coloredlogs.install(fmt='%(asctime)s %(levelname)s:: %(message)s',
                        datefmt='%H:%M:%S', level=loglevel, logger=log)


def sha256_hash(stream):
    """
    Compute the sha256 of the stream in input
    """
    stream.seek(0)
    sha256_hash = hashlib.sha256()
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: stream.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def server_init():
    """
    Server initialization: flask configuration, logging, etc.
    """
    # Check if SAMPLES_DIR folder is available
    if not os.path.isdir(SAMPLES_DIR):
        log.info("%s folder created" % SAMPLES_DIR)
        os.mkdir(SAMPLES_DIR)

    # Check if IDA_SAMPLES_DIR folder is available
    if not os.path.isdir(IDA_SAMPLES_DIR):
        log.info("%s folder created" % IDA_SAMPLES_DIR)
        os.mkdir(IDA_SAMPLES_DIR)

    # Check if GHIDRA_PROJECT folder is available
    if not os.path.isdir(GHIDRA_PROJECT):
        log.info("%s folder created" % GHIDRA_PROJECT)
        os.mkdir(GHIDRA_PROJECT)

    # Check if GHIDRA_OUTPUT folder exists
    if not os.path.isdir(GHIDRA_OUTPUT):
        log.info("%s folder created" % GHIDRA_OUTPUT)
        os.mkdir(GHIDRA_OUTPUT)

    # 400 MB limit
    app.config["MAX_CONTENT_LENGTH"] = 400 * 1024 * 1024

    return


#############################################
#       GHIDRAAAS APIs                      #
#############################################

@app.route("/")
def index():
    """
    Index page
    """
    return ("Hi! This is Ghidraaas", 200)


@app.route("/ghidra/api/analyze_sample/", methods=["POST"])
def analyze_sample():
    """
    Upload a sample, save it on the file system,
    and launch Ghidra analysis.
    """
    try:
        if not request.files.get("sample"):
            raise BadRequest("sample is required")

        sample_content = request.files.get("sample").stream.read()
        if len(sample_content) == 0:
            raise BadRequest("Empty file received")

        stream = request.files.get("sample").stream
        sha256 = sha256_hash(stream)

        sample_path = os.path.join(SAMPLES_DIR, sha256)
        stream.seek(0)
        with open(sample_path, "wb") as f_out:
            f_out.write(stream.read())

        if not os.path.isfile(sample_path):
            raise BadRequest("File saving failure")

        log.debug("New sample saved (sha256: %s)" % sha256)

        # Check if the sample has been analyzed
        project_path = os.path.join(GHIDRA_PROJECT, sha256 + ".gpr")
        if not os.path.isfile(project_path):
            log.debug("Ghidra analysis started")

            # Import the sample in Ghidra and perform the analysis
            command = [GHIDRA_HEADLESS,
                       GHIDRA_PROJECT,
                       sha256,
                       "-import",
                       sample_path]
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            p.wait()
            print(''.join(s.decode("utf-8") for s in list(p.stdout)))
            log.debug("Ghidra analysis completed")

        os.remove(sample_path)
        log.debug("Sample removed")
        return ("Analysis completed", 200)

    except BadRequest:
        raise

    except Exception:
        raise BadRequest("Sample analysis failed")


@app.route("/ghidra/api/get_functions_list_detailed/<string:sha256>")
def get_functions_list_detailed(sha256):
    """
    Given the sha256 of a sample, returns the list of functions.
    If the sample has not been analyzed, returns an error.
    """
    try:
        project_path = os.path.join(GHIDRA_PROJECT, sha256 + ".gpr")
        # Check if the sample has been analyzed
        if os.path.isfile(project_path):
            output_path = os.path.join(
                GHIDRA_OUTPUT, sha256 + "functions_list_a.json")

            command = [GHIDRA_HEADLESS,
                       GHIDRA_PROJECT,
                       sha256,
                       "-process",
                       sha256,
                       "-noanalysis",
                       "-scriptPath",
                       GHIDRA_SCRIPT,
                       "-postScript",
                       "FunctionsListA.py",
                       output_path,
                       "-log",
                       "ghidra_log.txt"]
            # Execute Ghidra plugin
            log.debug("Ghidra analysis started")
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            p.wait()
            print(''.join(s.decode("utf-8") for s in list(p.stdout)))
            log.debug("Ghidra analysis completed")

            # Check if JSON response is available
            if os.path.isfile(output_path):
                with open(output_path) as f_in:
                    return (f_in.read(), 200)
            else:
                raise BadRequest("FunctionsList plugin failure")
        else:
            raise BadRequest("Sample has not been analyzed")

    except BadRequest:
        raise

    except Exception:
        raise BadRequest("Sample analysis failed")


@app.route("/ghidra/api/get_functions_list/<string:sha256>")
def get_functions_list(sha256):
    """
    Given the sha256 of a sample, returns the list of functions.
    If the sample has not been analyzed, returns an error.
    """
    try:
        project_path = os.path.join(GHIDRA_PROJECT, sha256 + ".gpr")
        # Check if the sample has been analyzed
        if os.path.isfile(project_path):
            output_path = os.path.join(
                GHIDRA_OUTPUT, sha256 + "functions_list.json")
            command = [GHIDRA_HEADLESS,
                       GHIDRA_PROJECT,
                       sha256,
                       "-process",
                       sha256,
                       "-noanalysis",
                       "-scriptPath",
                       GHIDRA_SCRIPT,
                       "-postScript",
                       "FunctionsList.py",
                       output_path,
                       "-log",
                       "ghidra_log.txt"]
            # Execute Ghidra plugin
            log.debug("Ghidra analysis started")
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            p.wait()
            print(''.join(s.decode("utf-8") for s in list(p.stdout)))
            log.debug("Ghidra analysis completed")

            # Check if JSON response is available
            if os.path.isfile(output_path):
                with open(output_path) as f_in:
                    return (f_in.read(), 200)
            else:
                raise BadRequest("FunctionsList plugin failure")
        else:
            raise BadRequest("Sample has not been analyzed")

    except BadRequest:
        raise

    except Exception:
        raise BadRequest("Sample analysis failed")


@app.route("/ghidra/api/get_decompiled_function/<string:sha256>/<string:offset>")
def get_decompiled_function(sha256, offset):
    """
    Given a sha256, and an offset, returns the decompiled code of the
    function. Returns an error if the sample has not been analyzed by Ghidra,
    or if the offset does not correspond to a function
    """
    try:
        project_path = os.path.join(GHIDRA_PROJECT, sha256 + ".gpr")
        # Check if the sample has been analyzed
        if os.path.isfile(project_path):
            output_path = os.path.join(
                GHIDRA_OUTPUT, sha256 + "function_decompiled.json")
            # Call the DecompileFunction Ghidra plugin
            command = [GHIDRA_HEADLESS,
                       GHIDRA_PROJECT,
                       sha256,
                       "-process",
                       sha256,
                       "-noanalysis",
                       "-scriptPath",
                       GHIDRA_SCRIPT,
                       "-postScript",
                       "FunctionDecompile.py",
                       offset,
                       output_path,
                       "-log",
                       "ghidra_log.txt"]
            # Execute Ghidra plugin
            log.debug("Ghidra analysis started")
            p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            p.wait()
            print(''.join(s.decode("utf-8") for s in list(p.stdout)))
            log.debug("Ghidra analysis completed")

            # Check if the JSON response is available
            if os.path.isfile(output_path):
                with open(output_path) as f_in:
                    return (f_in.read(), 200)
            else:
                raise BadRequest("FunctionDecompile plugin failure")
        else:
            raise BadRequest("Sample has not been analyzed")

    except BadRequest:
        raise

    except Exception:
        raise BadRequest("Sample analysis failed")


@app.route("/ghidra/api/analysis_terminated/<string:sha256>")
def analysis_terminated(sha256):
    """
    Given a sha256, and an offset, remove the Ghidra project
    associated to that sample. Returns an error if the project does
    not exist.
    """
    try:
        project_path = os.path.join(GHIDRA_PROJECT, sha256 + ".gpr")
        project_folder_path = os.path.join(GHIDRA_PROJECT, sha256 + ".rep")
        # Check if the sample has been analyzed
        if os.path.isfile(project_path) and os.path.isdir(project_folder_path):
            os.remove(project_path)
            log.debug("Ghidra project .gpr removed")
            shutil.rmtree(project_folder_path)
            log.debug("Ghidra project folder .rep removed")
            return ("Analysis terminated", 200)
        else:
            raise BadRequest("Sample does not exist.")

    except BadRequest:
        raise

    except Exception:
        raise BadRequest("Analysis terminated failed")


#############################################
#       GHIDRAAAS APIs for IDA plugin       #
#############################################

@app.route("/ghidra/api/ida_plugin_checkin/", methods=["POST"])
def ida_plugin_checkin():
    """
    Submit the .bytes file to ghidraaas for future decompilation
    """
    try:
        # Process the bytes file
        if not request.files.get("bytes"):
            raise BadRequest(".bytes file is required")

        sample_content = request.files.get("bytes").stream.read()
        if len(sample_content) == 0:
            raise BadRequest("Empty file .bytes received")

        # Process metadata associated to the bytes file
        if not request.files.get("data"):
            raise BadRequest("data is required")
        data = json.loads(request.files['data'].stream.read().decode('utf-8'))

        # Using md5, since IDA stores it in the IDB
        md5 = data.get('md5', None)
        if not md5:
            raise BadRequest("md5 hash is required")
        filename = data.get("filename", None)
        if not filename:
            raise BadRequest("filename is required")

        stream = request.files.get("bytes").stream
        binary_file_path = os.path.join(IDA_SAMPLES_DIR, "%s.bytes" % filename)
        stream.seek(0)
        with open(binary_file_path, "wb") as f_out:
            f_out.write(stream.read())

        if not os.path.isfile(binary_file_path):
            raise BadRequest("File saving failure")

        log.debug("New binary file saved (filename: %s)" % filename)
        return (json.dumps({
            "status": "ok"
        }), 200)

    except BadRequest:
        raise

    except Exception:
        log.exception("IDA plugin checkin failed")
        raise BadRequest("IDA plugin checkin failed")


@app.route("/ghidra/api/ida_plugin_get_decompiled_function/", methods=["POST"])
def ida_plugin_get_decompiled_function():
    """
    Run the script to decompile a function starting
    from the xml project exported from IDA.
    """
    try:
        # Process the xml file
        if not request.files.get("xml"):
            raise BadRequest(".xml file is required")

        sample_content = request.files.get("xml").stream.read()
        if len(sample_content) == 0:
            raise BadRequest("Empty file .xml received")

        # Process metadata associated with the request
        if not request.files.get("data"):
            raise BadRequest("data is required")
        data = json.loads(request.files['data'].stream.read().decode('utf-8'))

        # Using md5, since IDA stores it in the IDB
        md5 = data.get('md5', None)
        if not md5:
            raise BadRequest("md5 hash is required")
        filename = data.get("filename", None)
        if not filename:
            raise BadRequest("filename is required")
        address = data.get('address', None)
        if not address:
            raise BadRequest("address is required")

        stream = request.files.get("xml").stream
        xml_file_path = os.path.join(IDA_SAMPLES_DIR, "%s.xml" % filename)
        stream.seek(0)
        with open(xml_file_path, "wb") as f_out:
            f_out.write(stream.read())

        if not os.path.isfile(xml_file_path):
            raise BadRequest("File saving failure")

        log.debug("New xml file saved (filename: %s)" % filename)

        b_filename = filename + ".bytes"
        if not os.path.isfile(os.path.join(IDA_SAMPLES_DIR, b_filename)):
            raise BadRequest("Bytes file not exist")

        output_path = os.path.join(
            GHIDRA_OUTPUT, "%s_dec_%s.json" % (md5, address))

        cmd = [GHIDRA_HEADLESS,
               ".",
               "Temp",
               "-import",
               xml_file_path,
               '-scriptPath',
               GHIDRA_SCRIPT,
               '-postScript',
               'FunctionDecompile.py',
               address,
               output_path,
               "-noanalysis",
               "-deleteProject",
               "-log",
               "ghidra_log.txt"]

        # Execute Ghidra plugin
        log.debug("Ghidra analysis started")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        p.wait()
        print(''.join(s.decode("utf-8") for s in list(p.stdout)))
        log.debug("Ghidra analysis completed")

        # Check if the JSON response is available
        response = None
        if os.path.isfile(output_path):
            with open(output_path) as f_in:
                response = f_in.read()

        if response:
            try:
                os.remove(xml_file_path)
                log.debug("File %s removed", xml_file_path)
            except Exception:
                pass
            try:
                os.remove(output_path)
                log.debug("File %s removed", output_path)
            except Exception:
                pass
            return (response, 200)
        else:
            raise BadRequest("IDA plugin decompilation failed")

    except BadRequest:
        raise

    except Exception:
        log.exception("IDA plugin decompilation failed")
        raise BadRequest("IDA plugin decompilation failed")


@app.route("/ghidra/api/ida_plugin_checkout/", methods=["POST"])
def ida_plugin_checkout():
    """
    Remove files associated with the sample requesting checkout
    """
    try:
        if not request.json:
            raise BadRequest("json data required")

        j = json.loads(request.json)
        md5 = j.get("md5", None)
        if not md5:
            raise BadRequest("md5 hash is required")
        filename = j.get("filename", None)
        if not filename:
            raise BadRequest("filename is required")

        binary_file_path = os.path.join(IDA_SAMPLES_DIR, "%s.bytes" % filename)
        if os.path.isfile(binary_file_path):
            os.remove(binary_file_path)
            log.debug("File %s removed", binary_file_path)

        return ("OK", 200)

    except BadRequest:
        raise

    except Exception:
        log.exception("IDA plugin checkout failed")
        raise BadRequest("IDA plugin checkout failed")


#############################################
#       ERROR HANDLING                      #
#############################################
@app.errorhandler(BadRequest)
@app.errorhandler(HTTPException)
@app.errorhandler(Exception)
def handle_error(e):
    """
    Manage logging and responses in case of error.
    """
    if isinstance(e, HTTPException):
        return (str(e), e.code)
    else:
        return (traceback.format_exc(), 500)


set_logger(True)
server_init()
