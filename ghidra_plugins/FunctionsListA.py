#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  FunctionsListA - Ghidra plugin                                            #
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

import base64
import hashlib
import json
import sys

try:
    args = getScriptArgs()
    response_dict = dict()

    if len(args) < 1:
        print("usage: ./FunctionsList.py output_path")
        sys.exit(0)

    # output_path of the json file (should terminate with ".json")
    output_path = args[0]
    functions_dict = dict()

    # Create a dictionary of address - function names
    functionIterator = currentProgram.getFunctionManager().getFunctions(True)
    for c, function in enumerate(functionIterator):
        try:
            range = function.getBody().getFirstRange()
            if range != None:
                length = int(range.getMaxAddress().subtract(
                    range.getMinAddress())) + 1
                size = hex(length).strip("L")
                bbytes = getBytes(function.getEntryPoint(), length)
                uints = [x & 0xff for x in bbytes]
                sha256 = hashlib.sha256(str(bytearray(uints))).hexdigest()
                b64 = base64.b64encode(bytearray(uints))
                address = function.getEntryPoint().getOffset()
                start_addr = hex(address).strip("L")

                function_d = dict()
                function_d['func_bytes'] = b64
                function_d['func_name'] = function.getName().strip("`\'")
                function_d['sha256'] = sha256
                function_d['size'] = size
                function_d['start_addr'] = start_addr
                functions_dict[sha256] = function_d

        except ghidra.program.model.mem.MemoryAccessException:
            # Skipping function
            pass

    # Create a dictionary for the json response
    response_dict['status'] = "completed"
    response_dict['functions_list'] = functions_dict
    print("Found %d functions" % (c + 1))

    with open(output_path, "w") as f_out:
        json.dump(response_dict, f_out)
    print("Json saved to %s" % output_path)

except Exception:
    response_dict['status'] = "error"
    print(json.dumps(response_dict))
