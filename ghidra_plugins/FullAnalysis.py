#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys

try:
    args = getScriptArgs()
    response_dict = dict()

    if len(args) < 1:
        print("usage: ./FullAnalysis.py output_path")
        sys.exit(0)

    # output_path of the json file (should terminate with ".json")
    output_path = args[0]
    symbols = list()
    external = dict()
    sm = currentProgram.getSymbolTable()
    symb = sm.getExternalSymbols()
    c = 0
    for s in symb:
        namespace = s.getParentNamespace().getName()
        if namespace not in external.keys():
            external[namespace] = []
        external[namespace].append(s.getName())
        c+=1
    # Create a dictionary of address - function names
    
    response_dict['External Symbols'] = external

    print("Found %d external symbols" % (c))

    with open(output_path, "w") as f_out:
        json.dump(response_dict, f_out)
    print("Json saved to %s" % output_path)

except Exception:
    response_dict['status'] = "error"
    print(json.dumps(response_dict))