#!/usr/bin/env python3

import re
import os
import json
from pathlib import Path
from collections import defaultdict
import fileinput

def flag_suspicious_permissions(content,cwd):
    
    try:
        with open(Path(cwd+"/rules/permissions.json"), "r") as outfile:
            suspicious_permissions = json.load(outfile)
    except:
        print("cannot open ruleset permissions.json")
        return ["cannot find ruleset"]
    permissions = re.findall(r"android\.permission\.\w+", content)
    return list([perm for perm in permissions if perm in suspicious_permissions])

def flag_suspicious_urls(content,cwd):
    flagged_urls = []

    try:
        with open(Path(cwd+"/rules/url.json"), "r") as outfile:
            suspicious_urls = json.load(outfile)
    except:
        print("cannot open file url.json")
        return ["cannot find ruleset"]

    for url_pattern in suspicious_urls:
        matches = re.findall(url_pattern, content)
        flagged_urls.extend(matches)
    return list(flagged_urls)

def flag_suspicious_code_and_apis(content,cwd):
    flagged_code_and_apis = []

    try:
        with open(Path(cwd+"/rules/code_apis.json"), "r") as outfile:
            suspicious_code_and_apis = json.load(outfile)
    except:
        print("cannot open file code_apis.json")
        return ["cannot find ruleset"]

    for snippet in suspicious_code_and_apis:
        matches = re.findall(".*?" + snippet+".*?\n", content)
        flagged_code_and_apis.extend(matches)
    flagged_code_and_apis = [intent.strip() for intent in flagged_code_and_apis]
    
    return list(flagged_code_and_apis)

'''
def flag_suspicious_policies(content):
    return list([policy for policy in suspicious_policies if policy in content])
'''
def flag_suspicious_logging(content,cwd):
    flagged_logging = []

    try:
        with open(Path(cwd+"/rules/logging.json"), "r") as outfile:
            suspicious_logging = json.load(outfile)
    except:
        print("cannot open file logging.json")
        return ["cannot find ruleset"]

    for log in suspicious_logging:
        matches = re.findall(".*?" + log +".*?\n", content)
        flagged_logging.extend(matches)
    return list(flagged_logging)

def flag_suspicious_intents(file_path, content,cwd):
    flagged_intents = []

    try:
        with open(Path(cwd+"/rules/intents.json"), "r") as outfile:
            suspicious_intents = json.load(outfile)
    except:
        print("cannot open file intents.json")
        return ["cannot find ruleset"]

    for intent in suspicious_intents:
        
        if (file_path.split("/")[-1]== "AndroidManifest.xml"):
            #<action android:name=”android.accessibilityservice.AccessibilityService”/>
            matches = re.findall("<intent-filter>(.*?)</intent-filter>", content,  re.IGNORECASE | re.DOTALL)
        else:
            matches = re.findall(".*?" + intent+".*?\n", content, re.IGNORECASE)
        flagged_intents.extend(matches)
    flagged_intents = [intent.strip() for intent in flagged_intents]
    return list(flagged_intents)

def flag_suspicious_extras(content,cwd):
    flagged_extras = []

    try:
        with open(Path(cwd+"/rules/extras.json"), "r") as outfile:
            suspicious_extras = json.load(outfile)
    except:
        print("cannot open file extras.json")
        return ["cannot find ruleset"]
    
    for extra in suspicious_extras:
        matches = re.findall(".*?" + extra+".*?\n", content)
        flagged_extras.extend(matches)
    return list(flagged_extras)

def flag_suspicious_patterns(content, patterns, output, file_name):
    for pattern in patterns:
        output[pattern["category"]][file_name] = []
        for match in re.finditer(pattern["suspicious"], content):
            line = content[match.start():content.find('\n', match.start())]
            
            output[pattern["category"]][file_name].append(line)

        output[pattern["category"]]['suspicious'] = pattern.get("legitimate", "")
        output[pattern["category"]]['abuse'] = pattern.get("abuse", "")
        
    return output

def scan_file(file_path, cwd, options, output):
    file_name = file_path.split("/")[-1]
    
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        content = content.decode('utf-8', errors='ignore')
        
        path_to_json = './rules/'
        json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
        for file_path in json_files:
            try:
                with open(file_path, "r") as outfile:
                    ruleset = json.load(outfile)
                    output = flag_suspicious_patterns(content, ruleset, output, file_name) if options[file_path] else list()
                return output
            except (json.decoder.JSONDecodeError):
                print("Error occured with "+ file_path)
            

    except Exception as e:
        print(f"Error: {e}")
        return output


'''
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