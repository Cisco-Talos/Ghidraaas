#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  FunctionsList - Ghidra plugin                                             #
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
        key = hex(function.getEntryPoint().getOffset())
        functions_dict[key] = function.getName()

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
