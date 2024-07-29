#!/usr/bin/env python3

import re
import os
import json
from pathlib import Path
from collections import defaultdict
import fileinput


def flag_suspicious_patterns(content, ruleset, ruleset_name, output, file_path):
    '''
    Analyzes file for any matches in rulesets

    Parameters:
        content (string): String of entire file contents
        ruleset (list): List of ruleset
        ruleset_name (string): name of ruleset

    Returns:
        output (dictionary): Dictionary of all flaggd strings
    '''
    if (ruleset_name !="code apis" and file_path not in output[ruleset_name]):
        output[ruleset_name][file_path] = []
    for pattern in ruleset:
        if (ruleset_name =="code apis" and file_path not in output[ruleset_name][pattern["category"]]):
            output[ruleset_name][pattern["category"]][file_path] = []
        for match in re.finditer("(?<=\\n)[^\\n]*"+pattern["suspicious"]+"[^\\n]*(?=\\n)", content, re.I):
            line = content[match.start():content.find('\n', match.start())]
            start_pos = match.start()
            line_number = content.count('\n', 0, start_pos) + 1
            if (file_path == "AndroidManifest.xml" and ruleset_name =="permissions"):
                output[ruleset_name][file_path].append({
                    "line number": line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse": pattern.get("abuse", "")
                })

            elif (ruleset_name =="code apis"):
                output[ruleset_name][pattern["category"]][file_path].append({
                    "line number": line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse": pattern.get("abuse", "")
                })
                
            else:
                output[ruleset_name][file_path].append({
                    "line number": line_number,
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse": pattern.get("abuse", "")
                })

        if (ruleset_name == "code apis"):
            if (len(output[ruleset_name][pattern["category"]][file_path]) == 0):
                output[ruleset_name][pattern["category"]].pop(file_path)

    if (ruleset_name != "code apis" ):
        if (len(output[ruleset_name][file_path]) == 0):
            output[ruleset_name].pop(file_path)

    return output

def scan_file(file_path, options, output):
    '''
    Analyzes file for any matches in rulesets

    Parameters:
        file_path (string): String of file path
        options (dictionary): Dictionary of the options of the rulesets
        output (dictionary): Dictionary of all flaggd strings

    Returns:
        output (dictionary): Dictionary of all flaggd strings
    '''
    with open(file_path, 'rb') as file:
        content = file.read()
    content = content.decode('utf-8', errors='ignore')

    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]

    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if options[rule_path]:
                # print(f"Processing {rule_path} for {file_path}")
                output = flag_suspicious_patterns(content, ruleset, rule_path.split("/")[-1].split(".")[0], output, file_path)
        except (json.decoder.JSONDecodeError) as e:
            print(f"Error occurred with {rule_path}: {e}")

    return output
