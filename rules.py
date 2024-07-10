#!/usr/bin/env python3

import re
import os
import json
from pathlib import Path
from collections import defaultdict
import fileinput


def flag_suspicious_patterns(content, ruleset, ruleset_name, output, file_path):
    if (ruleset_name !="code_apis" and file_path not in output[ruleset_name]):
        output[ruleset_name][file_path] = []
    for pattern in ruleset:
        if (ruleset_name =="code_apis" and file_path not in output[ruleset_name][pattern["category"]]):
             output[ruleset_name][pattern["category"]][file_path] = []
        for match in re.finditer("(?<=\\n)[^\\n]*"+pattern["suspicious"]+"[^\\n]*(?=\\n)", content, re.I):
            line = content[match.start():content.find('\n', match.start())]
            start_pos = match.start()
            line_number = content.count('\n', 0, start_pos) + 1
            if (file_path == "AndroidManifest.xml" and ruleset_name =="permissions"):
                output[ruleset_name][file_path].append({
                    "line number":line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
                
            elif (ruleset_name =="code_apis"):
                output[ruleset_name][pattern["category"]][file_path].append({
                    "line number":line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
            else:
                
                output[ruleset_name][file_path].append({
                    "line number":line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
        
        if (ruleset_name == "code_apis"):
            if (len(output[ruleset_name][pattern["category"]][file_path])==0):
                
                output[ruleset_name][pattern["category"]].pop(file_path)
    
    if (ruleset_name != "code_apis" ):
        
        if (len(output[ruleset_name][file_path]) == 0):
            
            output[ruleset_name].pop(file_path)
        
    return output



def scan_file(file_path, cwd, options, output):
    
    file_name = file_path.split("/")[-1]
    #try:
    with open(file_path, 'rb') as file:
        content = file.read()
    content = content.decode('utf-8', errors='ignore')
    
    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
        
    
    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if (options[rule_path]):
                output = flag_suspicious_patterns(content, ruleset, rule_path.split("/")[-1].split(".")[0], output, file_path)
            
        except (json.decoder.JSONDecodeError):
            print("Error occured with "+ rule_path)

    return output
