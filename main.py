#!/usr/bin/env python3
# python3 2.12.3
import os
from pathlib import Path
import rules
import json
import argparse
import sys
import subprocess
from prettytable import PrettyTable, MARKDOWN
import itertools
import hashlib
import re

def get_identifier_from_path(path):
    parts = path.split(os.sep)
    parts = [part for part in parts if part]
    return parts[-2] if len(parts) > 1 else parts[-1]

def get_unique_filename(base_name, extension, directory="."):
    counter = 1
    unique_name = f"{base_name}{extension}"
    while os.path.exists(os.path.join(directory, unique_name)):
        unique_name = f"{base_name}_{counter}{extension}"
        counter += 1
    return unique_name

def check_folders(directory, cwd, options):
    first_iteration = True
    android_manifest_found = False
    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
    output = {}
    identifier = get_identifier_from_path(directory)

    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if options[rule_path]:
                create_output(ruleset, rule_path.split("/")[-1].split(".")[0], output)
        except (json.decoder.JSONDecodeError):
            print("Error occurred with " + rule_path)
    
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
                
                output = rules.scan_file(file_path, cwd, options, output)
    
    if output:
        json_update(output, identifier)
    return output
    
def create_output(ruleset, ruleset_name, output):
    
    output[ruleset_name] = {}
    for pattern in ruleset:
        if (ruleset_name =="code_apis"):
            output[ruleset_name][pattern["category"]] = {}
    return output

def json_update(output, identifier):
    output_filename = get_unique_filename(f"{identifier}", ".json")
    with open(output_filename, "w+") as outfile:
        json.dump(output, outfile, indent=1)

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
    try:
        with open(directory, "rb") as file:
            content = file.read()
            content = content.decode('utf-8', errors='ignore')
            digest = hashlib.file_digest(file, "md5")
        if (method == "java"):
            with open(outputpath+"/jadx_decompiled/resources/AndroidManifest.xml", "r", encoding="utf-8") as file:
                content = file.read()

        elif (method == "smali"):
            with open(outputpath+"/apktool_decompiled/AndroidManifest.xml", "r", encoding="utf-8") as file:
                content = file.read()
        package_name = re.findall(r'(package=\")(.*?)(\")', content)[0][1]
        stat = {
            "file_size": os.stat(directory).st_size/1000000,
            "MD5": digest.hexdigest(),
            "package name": package_name
        }

        with open(outputpath+'/file_stat.json', 'w') as outfile:
            json.dump(stat, outfile, indent=1)
    except:
        print("Error: Output folder '"+args.output+"' cannot be written into. Please check the folder and try again.")

def generate_html_table(data, directory, identifier):
    count = 0
    try:
        with open(directory + "/file_stat.json", "rb") as file:
            content = json.load(file)
    except:
        print("Error: file_stats.json not found. Please check if path is a decompiled apk and try again.")
        content = {
            "file_size": None,
            "MD5": None,
            "package name": None
        }
    empty = True
    html = '<html><head><title>Flagged Results</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script></head><body>'

    html += '\n<div class="container"><div class="row">'
    html += f'<div class="col"><p>Package name:</p></div><div class="col"><p>{content["package name"]}</p></div></div>'
    
    html += '<div class="row">'
    html += f'<div class="col"><p>File size:</p></div><div class="col"><p>{content["file_size"]}MB</p></div></div>'
    
    html += '<div class="row">'
    html += f'<div class="col"><p>MD5:</p></div><div class="col"><p>{content["MD5"]}</p></div></div>'

    html += '\n<h1 class="text-center">Categories</h1>\n'
    html += '\n<div class="accordion container" id="accordionPanel">\n'
    for section, files in data.items():
        html += '\t<div class="accordion-item">\n'
        html += f'\t\t<h2 class="accordion-header" id="heading{section.replace(" ", "")}">\n'
        html += f'\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{section}" aria-expanded="false" aria-controls="collapse{section}">{section}</button></h2>\n'
        html += f'\t\t\t\t<div id="collapse{section}" class="accordion-collapse collapse" aria-labelledby="heading{section.replace(" ", "")}" data-bs-parent="#accordionPanel">\n'
        html += f'\t\t\t\t\t<div class="accordion-body">\n'

        if section == "code_apis":
            html += f'\t\t\t\t\t\t<div class="accordion" id="sub-accordion{section.replace(" ", "")}">\n'

            for sub_section, files in data[section].items():
                if len(files) == 0:
                    empty = False
                else:
                    empty = True
                html += '\t\t\t\t\t\t\t<div class="accordion-item">\n'
                html += f'\t\t\t\t\t\t\t<h2 class="accordion-header" id="sub-heading{sub_section.replace(" ", "")}">\n'
                html += f'\t\t\t\t\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_section.replace(" ", "")}" aria-expanded="false" aria-controls="collapse{sub_section.replace(" ", "")}">{sub_section}</h2>\n'
                html += f'\t\t\t\t\t\t\t\t<div id="sub-collapse{sub_section.replace(" ", "")}" class="accordion-collapse collapse" aria-labelledby="sub-heading{sub_section.replace(" ", "")}" data-bs-parent="#sub-accordion{section.replace(" ", "")}">\n'
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
            if len(files) == 0:
                empty = True
            else:
                empty = True

            if section == "permissions":
                html += '\t\t\t\t\t\t<table class="table table-dark table-striped"><tr><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>\n'
                for file_name, list_details in files.items():
                    for detail in list_details:
                        html += f'\t\t\t\t\t\t<tr><td>{detail["suspicious"]}</td><td>{detail["legitimate"]}</td><td>{detail["abuse"]}</td></tr>'
            else:
                html += '\t\t\t\t\t\t<table class="table table-dark table-striped"><tr><th>File Name</th><Th>Details</th><th>Legitimate Use</th><Th>Abuse</th></tr>\n'
                
                for file_name, list_details in files.items():
                    for detail in list_details:
                        html += f'\t\t\t\t\t\t<tr><td>{file_name}</td><td>{detail["suspicious"]}</td><td>{detail["legitimate"]}</td><td>{detail["abuse"]}</td></tr>\n'
            html += '\t\t\t\t\t\t</table>\n'

        html += '\t\t\t\t\t</div>\n'
        html += '\t\t\t\t</div>\n'
        html += '\t</div>\n'

    html += '</div></div>'

    html += '</body></html>'
    
    if empty:
        print("Error: No strings found. Please check if path is a decompiled apk and try again.")

    output_filename = get_unique_filename(f"{identifier}Analysis", ".html")
    with open(output_filename, "w+") as f:
        f.write(html)
    print(f"Saved output as {output_filename}")
    
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
        if not Path(args.output).is_dir():
            print("Error: Output folder '"+args.output+"' not found. Please check the folder and try again.")
        elif os.path.isfile(args.path) and args.path.split(".")[-1] == "apk":
            decompile(args.path, cwd, args.decompile_method, args.output)
        else:
            print("Error: File '"+args.path+"' not found. Please check the filename and try again.")
    else:
        identifier = get_identifier_from_path(args.path)
        if args.very_verbose:
            options = {
                "./rules/permissions.json": True,
                "./rules/url.json": True,
                "./rules/code_apis.json": True,
                "./rules/intents.json": True,
                "./rules/logging.json": True,
                "./rules/extras.json": True,
            }
            output = check_folders(args.path, cwd, options)
            non_verbose_mode = False
        elif non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging or args.extras):
            options = {
                "./rules/permissions.json": args.permissions,
                "./rules/url.json": args.urls,
                "./rules/code_apis.json": args.apis,
                "./rules/intents.json": args.intents,
                "./rules/logging.json": args.logging,
                "./rules/extras.json": args.extras,
            }
            output = check_folders(args.path, cwd, options)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
        
        generate_html_table(output, args.path.split("/")[0], identifier)
