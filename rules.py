#!/usr/bin/env python3

import re
import os
import json
from pathlib import Path
from collections import defaultdict
import fileinput


def flag_suspicious_patterns(content, ruleset, ruleset_name, output, file_name):
    if (ruleset_name !="code_apis" and file_name not in output[ruleset_name]):
        output[ruleset_name][file_name] = []
    for pattern in ruleset:
        if (ruleset_name =="code_apis" and file_name not in output[ruleset_name][pattern["category"]]):
             output[ruleset_name][pattern["category"]][file_name] = []
        for match in re.finditer(pattern["suspicious"], content):
            line = content[match.start():content.find('\n', match.start())]
            
            if (file_name == "AndroidManifest.xml" and ruleset_name =="permissions"):
                print(output[ruleset_name])
                print()
                output[ruleset_name][file_name].append({
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
                
            elif (ruleset_name =="code_apis"):
                output[ruleset_name][pattern["category"]][file_name].append({
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
            else:
                
                output[ruleset_name][file_name].append({
                    "suspicious": line,
                    "legitimate": pattern.get("legitimate", ""),
                    "abuse":pattern.get("abuse", "")
                })
        
        if (ruleset_name =="code_apis"):
            if (len(output[ruleset_name][pattern["category"]][file_name])==0):
                
                output[ruleset_name][pattern["category"]].pop(file_name)
    
    if (ruleset_name != "code_apis" ):
        
        if (len(output[ruleset_name][file_name]) == 0):
            
            output[ruleset_name].pop(file_name)
        

    #if (len(output[pattern["category"]]) !=0):
        #output[pattern["category"]]['suspicious'] = pattern.get("legitimate", "")
        #output[pattern["category"]]['abuse'] = pattern.get("abuse", "")
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
                output = flag_suspicious_patterns(content, ruleset, rule_path.split("/")[-1].split(".")[0], output, file_name)
            
        except (json.decoder.JSONDecodeError):
            print("Error occured with "+ rule_path)
    return output
'''
    except Exception as e:
        print(f"Error: {e}")
        return output



def scan_file(file_path, scan_permissions, scan_urls, scan_code_and_apis, scan_intents, scan_logging, scan_extras):
    cwd = os.path.dirname(__file__)
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        flagged_permissions = flag_suspicious_permissions(content,cwd) if scan_permissions else list()
        flagged_urls = flag_suspicious_urls(content,cwd) if scan_urls else list()
        flagged_code_and_apis = flag_suspicious_code_and_apis(content,cwd) if scan_code_and_apis else list()
        flagged_logging = flag_suspicious_logging(content,cwd) if scan_logging else list()
        flagged_intents = flag_suspicious_intents(file_path, content,cwd) if scan_intents else list()
        flagged_extras = flag_suspicious_extras(content,cwd) if scan_extras else list()
        
        return [flagged_permissions, flagged_urls, flagged_code_and_apis,
                flagged_logging, flagged_intents, flagged_extras]
    except Exception as e:
        print(f"Error: {e}")
        return [list(), list(), list(), list(), list(), list(), list()]

def scan_folder(folder_path, scan_permissions, scan_urls, scan_code_and_apis, scan_policies, scan_logging, scan_intents, scan_extras):
    results = defaultdict(lambda: defaultdict(list))
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            (flagged_permissions, flagged_urls, flagged_code_and_apis, 
             flagged_logging, flagged_intents, flagged_extras) = scan_file(
                file_path, scan_permissions, scan_urls, scan_code_and_apis, scan_policies,
                scan_logging, scan_intents, scan_extras)

            if flagged_permissions:
                results['permissions'][file_path].update(flagged_permissions)
            if flagged_urls:
                results['urls'][file_path].update(flagged_urls)
            if flagged_code_and_apis:
                results['code_and_apis'][file_path].update(flagged_code_and_apis)
            if flagged_logging:
                results['logging'][file_path].update(flagged_logging)
            if flagged_intents:
                results['intents'][file_path].update(flagged_intents)
            if flagged_extras:
                results['extras'][file_path].update(flagged_extras)

    return results

def print_results(results):
    for category, files in results.items():
        if category == 'permissions':
            print("\nFlagged Permissions:")
        elif category == 'urls':
            print("\nFlagged URLs:")
        elif category == 'code_and_apis':
            print("\nFlagged Code Snippets and APIs:")
        elif category == 'policies':
            print("\nFlagged Policies:")
        elif category == 'logging':
            print("\nFlagged Logging:")
        elif category == 'intents':
            print("\nFlagged Intents:")
        elif category == 'extras':
            print("\nFlagged Extras:")
            

        for file_path, items in files.items():
            print(f"  File: {file_path}")
            for item in items:
                print(f"    - {item}")
'''