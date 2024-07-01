#!/usr/bin/env python3
import os
from pathlib import Path
import rules
import json
import argparse
import sys
import subprocess
import rules
from prettytable import PrettyTable, MARKDOWN
import itertools
import hashlib
import re

def check_folders(directory, cwd, options):
    first_iteration = True
    android_manifest_found = False
    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
    output = {
    }
    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if (options[rule_path]):
                create_output(ruleset, rule_path.split("/")[-1].split(".")[0], output)
        except (json.decoder.JSONDecodeError):
            print("Error occured with "+ rule_path)
    

    json_create()
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java" or extension == "smali":
                if filename == "AndroidManifest.xml":
                    android_manifest_found = True
                file_path = os.path.join(path, filename)
                
                output = rules.scan_file(file_path, cwd, options,output)
                
                #if any(results):
                '''
                    my_file = Path(cwd + "/flagged_files.json")
                    print("file not found")
                    if ((not my_file.is_file()) and first_iteration):
                        
                        json_create()
                        first_iteration = False
                        '''
    json_update(output)
    return output
    
def create_output(ruleset, ruleset_name, output):
    
    output[ruleset_name] = {}
    for pattern in ruleset:
        if (ruleset_name =="code_apis"):
            output[ruleset_name][pattern["category"]] = {}
    return output

def json_update(output):
    '''
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)
    file_name = list(file_info.keys())[0]
    data[file_name] = file_info[file_name]'''
    with open("flagged_files.json", "w+") as outfile:
        json.dump(output, outfile, indent=1)

def json_create():
    with open("flagged_files.json", "w+") as outfile:
        json.dump({}, outfile)

def decompile(directory, cwd, method, outputpath):
    if outputpath is None:
        outputpath = cwd
    if sys.platform == "linux" or sys.platform == "linux2":
        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.sh"), directory, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.
        print("finished")

    elif sys.platform == "win32":
        process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.

    with open(directory, "rb") as file:
        content = file.read()
        content = content.decode('utf-8', errors='ignore')
        digest = hashlib.file_digest(file, "md5")
        package_name = re.search(r'package=\".*\"', content)
    stat = {
        "file_size": os.stat(directory).st_size/1000000,
        "MD5": digest.hexdigest(),
        "package name": package_name
    }

    with open(outputpath+'file_stat.json', 'w') as outfile:
        json.dump(stat, outfile, indent=1)

def generate_html_table(data):
    count=0
    
    html = '<html><head><title>Flagged Results</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script></head><body>'
    #html += '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>'
    #html += '<table border="1">'
    #html += '<tr><th>C</th><th>Category</th><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>'
    html += '\n<h1 class="text-center">Categories</h1>\n'
    html += '\n<div class="accordion container" id="accordionPanel">\n'
    for section, files in data.items():
        html += '\t<div class="accordion-item">\n'
        html += f'\t\t<h2 class="accordion-header" id="heading{section.replace(' ', '')}">\n'
        html += f'\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{section}" aria-expanded="false" aria-controls="collapse{section}">{section}</button></h2>\n'
        html += f'\t\t\t\t<div id="collapse{section}" class="accordion-collapse collapse" aria-labelledby="heading{section.replace(' ', '')}" data-bs-parent="#accordionPanel">\n'
        html += f'\t\t\t\t\t<div class="accordion-body">\n'

        if (section == "code_apis"):
            html += f'\t\t\t\t\t\t<div class="accordion" id="sub-accordion{section.replace(' ', '')}">\n'

            for sub_section, files in data[section].items():
                html += '\t\t\t\t\t\t\t<div class="accordion-item">\n'
                html += f'\t\t\t\t\t\t\t<h2 class="accordion-header" id="sub-heading{sub_section.replace(' ', '')}">\n'
                html += f'\t\t\t\t\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_section.replace(' ', '')}" aria-expanded="false" aria-controls="collapse{sub_section.replace(' ', '')}">{sub_section}</h2>\n'
                html += f'\t\t\t\t\t\t\t\t<div id="sub-collapse{sub_section.replace(' ', '')}" class="accordion-collapse collapse" aria-labelledby="sub-heading{sub_section.replace(' ', '')}" data-bs-parent="#sub-accordion{section.replace(' ', '')}">\n'
                html += '\t\t\t\t\t\t\t\t\t<div class="accordion-body">\n'
                html += '\t\t\t\t\t\t\t\t\t<table class="table table-dark table-striped"><tr><th>File Name</th><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>\n'
                for file_name, list_details in files.items():
                    for detail in list_details:
                        html += f'\t\t\t\t\t\t\t\t\t<tr><td>{file_name}</td><td>{detail["suspicious"]}</td><td>{detail["legitimate"]}</td><td>{detail["abuse"]}</td></tr>\n'
                html += '\t\t\t\t\t\t\t\t\t</table>\n'
                html += '\t\t\t\t\t\t\t\t\t</div>\n'
                html += '\t\t\t\t\t\t\t\t</div>\n'
                html += '\t\t\t\t\t\t\t</div>\n'


        else:
            if (section == "permissions"):
                html += '\t\t\t\t\t\t<table class="table table-dark table-striped"><tr><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>\n'
                for file_name, list_details in files.items():
                    for detail in list_details:
                        html += f'\t\t\t\t\t\t<tr><td>{detail["suspicious"]}</td><td>{detail["legitimate"]}</td><td>{detail["abuse"]}</td></tr>'
            else:
                html += '\t\t\t\t\t\t<table class="table table-dark table-striped"><tr><th>File Name</th><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>\n'
                
                for file_name, list_details in files.items():
                    for detail in list_details:
                        html += f'\t\t\t\t\t\t<tr><td>{file_name}</td><td>{detail["suspicious"]}</td><td>{detail["legitimate"]}</td><td>{detail["abuse"]}</td></tr>\n'
            html += '\t\t\t\t\t\t</table>\n'

        html += '\t\t\t\t\t</div>\n'
        html += '\t\t\t\t</div>\n'
        html += '\t</div>\n'
    
    
    '''
    html += '<div class="container"><h1>Categories</h1>'
    html+= '<div class="accordion" id="accordionPanels">'
    for sections, files in data.items():
        count+=1
        html += f'<div class="accordion-item">'
        html += f'<h2 class="accordion-header" id="panelsStayOpen-heading{count}">'
        html += f'<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapse{count}" aria-expanded="false" aria-controls="panelsStayOpen-collapse{count}">{sections}</button></h2>'
        
        
        if (sections == "code_apis"):
            html += f'<div id="panelsStayOpen-collapse{count}" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-heading{count}" data-bs-parent="#accordionPanels"><div class="accordion-body">'
            html += '<div class="accordion-body">'
            html += f'<div class="accordion" id="sub-accordion{sections}">'
            for sub_section, flagged_files in data[sections].items():
                #html += f'<div class="accordion" id="sub-accordion{sub_section.split()[0]}"><div class="accordion-item">'
                
                html += f'<div class="accordion-item">'
                html == f'<h2 class="accordion-header" id="sub-heading{sub_section.split()[0]}">'
                html += f'<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_section.split()[0]}" aria-expanded="false" aria-controls="panelsStayOpen-collapse{count}">{sub_section}</button></h2>'
                html += f'<div id="sub-collapse{sub_section}" class="accordion-collapse collapse" aria-labelledby="sub-heading{sub_section.split()[0]}" data-bs-parent="sub-accordion{sections}"><div class="accordion-body"><table class="table"><thead class="thead-dark"><th scope="col">Details</th><th scope="col">Legitimate Use</th><th>Abuse</th></tr></thead><tbody>'
                for flagged_name, flagged_strings in flagged_files.items():
                    for string in flagged_strings:
                        html+=f'<tr><th scope="col">{flagged_name}</th><th scope="col">{string["suspicious"]}</th><th scope="col">{string["legitimate"]}</th><th scope="col">{string["abuse"]}</th></tr>'
                html +='</tbody></table></div></div></div>'
        html +='</div></div></div></div>'
        '''
    '''
        else:
            html+='<table class="table"><thead class="thead-dark"><th scope="col">Details</th><th scope="col">Legitimate Use</th><th>Abuse</th></tr></thead><tbody>'
            if (sections == "permissions"):
                html += f'<div id="panelsStayOpen-collapse{count}" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-heading{count}" data-bs-parent="#accordionPanels"><div class="accordion-body"><table class="table"><thead class="thead-dark"><th scope="col">Details</th><th scope="col">Legitimate Use</th><th>Abuse</th></tr></thead><tbody>'
            else:
                html += f'<div id="panelsStayOpen-collapse{count}" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-heading{count}" data-bs-parent="#accordionPanels"><div class="accordion-body"><table class="table"><thead class="thead-dark"><tr><th scope="col">File Name</th><th scope="col">Details</th><th scope="col">Legitimate Use</th><th>Abuse</th></tr></thead><tbody>'
            for file_name, file in enumerate(files):
                if (sections == "permissions"):
                    for flagged in data[sections][file]:
                        html+=f'<th scope="col">{flagged["suspicious"]}</th><th scope="col">{flagged["legitimate"]}</th><th scope="col">{flagged["abuse"]}</th></tr>'
                else:
                    for flagged in data[sections][file]:
                        html+=f'<tr><th scope="col">{file}</th><th scope="col">{flagged["suspicious"]}</th><th scope="col">{flagged["legitimate"]}</th><th scope="col">{flagged["abuse"]}</th></tr>'
            html +='</tbody></table></div></div>'
        '''
    html +='</div></div>'
    '''
    for file, info in enumerate(files):
        html += f'<tr><td>{file_name}</td><td>{category_name}</td><td>{details}</td><td>{legitimate}</td><td>{abuse}</td></tr>'
        for item in items:
            details = item.get("suspicious", "")
            legitimate = item.get("legitimate", "")
            abuse = item.get("abuse", "")
            html += f'<tr><td>{file_name}</td><td>{category_name}</td><td>{details}</td><td>{legitimate}</td><td>{abuse}</td></tr>'
    '''
    html += '</body></html>'
    
    

    with open('flagged_results.html', 'w') as f:
        f.write(html)
    print("Saved output as flagged_results.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="malwh", description="APK Analysis CLI Tool")
    
    subparsers = parser.add_subparsers(help='help for subcommand', required=True, dest="subcommand")
    parser.add_argument("path", help="full path of the apk", type=str)

    parser_decompile = subparsers.add_parser('decompile', help='Decompile help')
    parser_decompile.add_argument('decompile_method', help='decompilation method between java and smali', choices=('java', 'smali'))
    parser_decompile.add_argument('-o', '--output', help='output directory for decompiled source code', type=str)
    parser_analysis = subparsers.add_parser('analysis', help='Analysis help')

    parser_analysis.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-p", "--permissions", help="Scan for permissions", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-u", "--urls", help="List all URLs found in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-a", "--apis", help="List all APIs used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-i", "--intents", help="List all intents used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-l", "--logging", help="List all logging done in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-e", "--extras", help="List all extras used in the APK.", default=False, required=False, action="store_true")


    args = parser.parse_args()
    print(args)
    cwd = os.path.dirname(__file__)
    non_verbose_mode = True
    if not os.path.exists(args.path):
        print("Error: Folder/File '"+args.path+"' not found. Please check the path and try again.")
        sys.exit(1)

    if args.subcommand == "decompile":
        if os.path.isfile(args.path) and args.path.split(".")[-1] == "apk":
            decompile(args.path, cwd, args.decompile_method, args.output)
        else:
            print("Error: File '"+args.path+"' not found. Please check the filename and try again.")
    else:
        if args.very_verbose:
            options = {
                "./rules/permissions.json":True,
                "./rules/url.json":True,
                "./rules/code_apis.json":True,
                "./rules/intents.json":True,
                "./rules/logging.json":True,
                "./rules/extras.json":True,
            }
            output = check_folders(args.path, cwd, options)
            non_verbose_mode = False
        elif non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging or args.extras):
            options = {
                "./rules/permissions.json":args.permissions,
                "./rules/url.json":args.urls,
                "./rules/code_apis.json":args.apis,
                "./rules/intents.json":args.intents,
                "./rules/logging.json":args.logging,
                "./rules/extras.json":args.extras,
            }
            output = check_folders(args.path, cwd, options)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
        
    
        with open("flagged_files.json", "r") as outfile:
            data = json.load(outfile)

        generate_html_table(output) 

        # adding permissions to android manifest
        '''
        if (args.permissions or args.very_verbose or args.intents):
            table = PrettyTable(["File_name", "Permissions"])
            for key in data:
                if data[key][0]:  # Check if there are permissions flagged
                    table.add_row([key, data[key][0]])
            with open('permissions_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as permissions_examined.txt")
            table.clear()

            for key in data.keys():
                if ("AndroidManifest.xml" in key):
                    
                    print("android")
                    table.add_column("Permissions", data[key][0])
                    perms_table = table.get_string()
                    table.clear()

                    # adding intents to android manifest
                    table.add_column("Intents", data[key][4])

                    table_data = perms_table + "\n\n" + table.get_string()
                    with open('Android_manifest_examined.txt', 'w') as f:
                        f.write(table_data)
                    table.clear()
                    data.pop(key)
                    break

        if (args.urls or args.very_verbose):
            table = PrettyTable(["File_name", "URLs"])
            for key in data:
                if data[key][1]:  # Check if there are URLs flagged
                    table.add_row([key, data[key][1]])
            with open('urls_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as urls_examined.txt")
            table.clear()

        if (args.apis or args.very_verbose):
            table = PrettyTable(["File_name", "APIs"])
            for key in data:
                if data[key][2]:  # Check if there are APIs flagged
                    table.add_row([key, data[key][2]])
            with open('apis_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as apis_examined.txt")
            table.clear()

        if (args.apis or args.very_verbose):
            table = PrettyTable(["File_name", "APIs"])
            for key in data:
                if data[key][2]:  # Check if there are APIs flagged
                    table.add_row([key, data[key][2]])
            with open('apis_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as apis_examined.txt")
            table.clear()
        
        if (args.intents or args.very_verbose):
            table = PrettyTable(["File_name", "Intents"])
            for key in data:
                if data[key][4]:  # Check if there are intents flagged
                    table.add_row([key, data[key][4]])
            with open('intents_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as intents_examined.txt")
            table.clear()

        if (args.logging or args.very_verbose):
            table = PrettyTable(["File_name", "Logging"])
            for key in data:
                if data[key][3]:  # Check if there are logging flagged
                    table.add_row([key, data[key][3]])
            with open('logging_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as logging_examined.txt")
            table.clear()

        if (args.extras or args.very_verbose):
            table = PrettyTable(["File_name", "Extras"])
            for key in data:
                if data[key][5]:  # Check if there are extras flagged
                    table.add_row([key, data[key][5]])
            with open('extras_examined.txt', 'w') as f:
                f.write(table.get_string())
            print("Saved output as extras_examined.txt")
            table.clear()
    '''