#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  GhIDA: Ghidraaas - Ghidra as a Service                                    #
#                                                                            #
#  Copyright 2019 Andrea Marcelli, Cisco Talos                               #
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


import json
import requests

URL = "http://localhost:8080/ghidra/api"
BINARY = "test_files/a.out"
BYTES = "test_files/AAE30A28635D1D634F3D9BF9A04E0055_gYBqc.bytes"
XML = "test_files/AAE30A28635D1D634F3D9BF9A04E0055_gYBqc.xml"
SHA256 = "252ad75af5ba26cf432c10164635da0d3402e6963853052ea6a76d42180e7b69"


def sample_analysis():
    bb = {"sample": open(BINARY, "rb")}
    r = requests.post("%s/analyze_sample/" % URL, files=bb, timeout=300)
    print("sample_analysis status_code", r.status_code)
    if r.status_code == 200 or r.status_code == 204:
        return True
    print(r.text)
    return False


def get_function_list():
    r = requests.get("%s/get_functions_list/%s" %
                     (URL, SHA256), timeout=300)
    print("get_function_list status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def get_functions_list_detailed():
    r = requests.get("%s/get_functions_list_detailed/%s" %
                     (URL, SHA256), timeout=300)
    print("get_functions_list_detailed status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def get_decompiled_function():
    offset = "0x101020L"
    r = requests.get("%s/get_decompiled_function/%s/%s" %
                     (URL, SHA256, offset), timeout=300)
    print("get_decompiled_function status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def analysis_terminated():
    r = requests.get("%s/analysis_terminated/%s" %
                     (URL, SHA256), timeout=300)
    print("analysis_terminated status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def ghida_checkin():
    options = {
        "md5": "AAE30A28635D1D634F3D9BF9A04E0055",
        "filename": "AAE30A28635D1D634F3D9BF9A04E0055_gYBqc",
    }

    bb = [
        ('bytes', (BYTES, open(BYTES, 'rb'), 'application/octet')),
        ('data', ('data', json.dumps(options), 'application/json'))
    ]

    r = requests.post("%s/ida_plugin_checkin/" % URL, files=bb, timeout=300)
    print("ghida_checkin status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def ghida_decompile():
    options = {
        "md5": "AAE30A28635D1D634F3D9BF9A04E0055",
        "filename": "AAE30A28635D1D634F3D9BF9A04E0055_gYBqc",
        "address": '0x00402AED'
    }

    bb = [
        ('xml', (XML, open(XML, 'rb'), 'application/octet')),
        ('data', ('data', json.dumps(options), 'application/json'))
    ]

    r = requests.post("%s/ida_plugin_get_decompiled_function/" %
                      URL, files=bb, timeout=300)
    print("ghida_decompile status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def ghida_checkout():
    data = {
        "md5": "AAE30A28635D1D634F3D9BF9A04E0055",
        "filename": "AAE30A28635D1D634F3D9BF9A04E0055_gYBqc",
    }

    r = requests.post("%s/ida_plugin_checkout/" %
                      URL, json=json.dumps(data), timeout=300)
    print("ghida_checkout status_code", r.status_code)
    if r.status_code == 200:
        return True
    return False


def main():
    # Testing generic Ghidraaas APIs
    if not sample_analysis():
        print("sample_analysis test FAILED")
        return

    if not get_function_list():
        print("get_function_list test FAILED")
        return

    if not get_functions_list_detailed():
        print("get_functions_list_detailed test FAILED")
        return

    if not get_decompiled_function():
        print("get_decompiled_function test FAILED")
        return

    if not analysis_terminated():
        print("analysis_terminated test FAILED")
        return

    # Testing GhIDA APIs
    if not ghida_checkin():
        print("ghida_checkin test FAILED")
        return

    if not ghida_decompile():
        print("ghida_decompile test FAILED")
        return

    if not ghida_checkout():
        print("ghida_checkout test FAILED")
        return

    print("All tests PASSED")


main()
