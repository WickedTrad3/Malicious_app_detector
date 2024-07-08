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
import base64
import html
import time

def get_current_time():
    return time.strftime("%H-%M-%S-%d-%m-%Y")

def get_identifier_from_path(path):
    parts = path.split(os.sep)
    parts = [part for part in parts if part]
    return parts[-2] if len(parts) > 1 else parts[-1]

# def get_unique_directory_name(base_name, parent_directory="."):
#     counter = 1
#     unique_name = base_name
#     while os.path.exists(os.path.join(parent_directory, unique_name)):
#         unique_name = f"{base_name}_{counter}"
#         counter += 1
#     return unique_name


def get_unique_directory_name(base_name, parent_directory="."):
    # modified_name = f"{base_name}_{current_time}"
    # return modified_name
    current_time = get_current_time()
    return current_time

def check_folders(directory, cwd, options):
    first_iteration = True
    android_manifest_found = False
    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
    output = {}
    
    identifier = get_identifier_from_path(directory)
    new_directory_name = get_unique_directory_name(identifier, cwd)
    new_directory_path = os.path.join(cwd, new_directory_name)
    os.makedirs(new_directory_path, exist_ok=True)
    
    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if (options[rule_path]):
                create_output(ruleset, rule_path.split("/")[-1].split(".")[0], output)
        except (json.decoder.JSONDecodeError):
            print("Error occurred with " + rule_path)
    
    json_create(new_directory_path)
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

                #if any(results):
                '''
                    my_file = Path(cwd + "/flagged_files.json")
                    print("file not found")
                    if ((not my_file.is_file()) and first_iteration):
                        
                        json_create()
                        first_iteration = False
                        '''
    json_update(output, new_directory_path)
    return output

def create_output(ruleset, ruleset_name, output):
    output[ruleset_name] = {}
    for pattern in ruleset:
        if (ruleset_name =="code_apis"):
            output[ruleset_name][pattern["category"]] = {}
    return output

def json_update(output, new_directory_path):
    '''
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)
    file_name = list(file_info.keys())[0]
    data[file_name] = file_info[file_name]'''
    current_time = get_current_time()
    # with open(os.path.join(new_directory_path, current_time + ".json"), "w+") as outfile:
    # with open(os.path.join(new_directory_path, f"{new_directory_name}.json"), "w+") as outfile:
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:

        json.dump(output, outfile, indent=1)

def json_create(new_directory_path):
    current_time = get_current_time()
    # with open(os.path.join(new_directory_path, current_time + ".json"), "w+") as outfile:
    # with open(os.path.join(new_directory_path, f"{new_directory_name}.json"), "w+") as outfile:
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:
        json.dump({}, outfile)

def decompile(directory, cwd, method, outputpath):
    if outputpath is None:
        outputpath = cwd
    if sys.platform == "linux" or sys.platform == "linux2":
        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.sh"), directory, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.

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
        if (method == "java"):
        #change to include apktool_decompiled/jadx_decompiled folder
            with open(outputpath+"/jadx_decompiled/file_stat.json", 'w') as outfile:
                json.dump(stat, outfile, indent=1)
        else:
            with open(outputpath+"/apktool_decompiled/file_stat.json", 'w') as outfile:
                json.dump(stat, outfile, indent=1)
        print(f"Decompilation of {directory} complete. File metadata is stored inside flagged_items")
    except:
        print("Error: Output folder '" + outputpath + "' cannot be written into. Please check the folder and try again.")

def generate_html_table(data, icons, directory):
    count = 0
    try:
        with open(os.path.join(directory, "file_stat.json"), "rb") as file:
            content = json.load(file)
    except:
        print("Error: file_stats.json not found. Please check if path is a decompiled apk and try again.")
        content = {
            "file_size": None,
            "MD5": None,
            "package name": None
        }
    empty = True
    html_report = '<html><head><title>Flagged Results</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script></head>'
    html_report += '<style>.accordion {--bs-accordion-btn-color: white;--bs-accordion-btn-bg:  #2a2a2a;--bs-accordion-active-color: pink;--bs-accordion-active-bg:  #2a2a2a;}.accordion-button:after {background: #2a2a2a}.accordion-button:not(.collapsed)::after {background: #2a2a2a}</style>'
    html_report += '<body style="background-color:#121212;color: #b9b9b9;">'
    html_report += '\n<div class="container-fluid border border border-white rounded mt-2">'

    html_report += '<div class="row"><div class="col"><p>Malwhere</p></div><div class="col">'
    html_report += f'<div class="row"><div class="col"><p>Package name:</p></div><div class="col"><p>{content["package name"]}</p></div></div>'
    
    html_report += '<div class="row">'
    html_report += f'<div class="col"><p>File size:</p></div><div class="col"><p>{content["file_size"]}MB</p></div></div>'
    
    html_report += '<div class="row">'
    html_report += f'<div class="col"><p>MD5:</p></div><div class="col"><p>{content["MD5"]}</p></div></div></div></div></div>'

    html_report += '\n<h1 class="text-center">Categories</h1>\n'
    html_report += '\n<div class="accordion container-fluid" id="accordionPanel">\n'



    #image = open('./icons/code.svg', 'rb').read() # read bytes from file
    #data_base64 = base64.b64encode(image)  # encode to base64 (bytes)
    #data_base64 = data_base64.decode()
    for section, files in data.items():
        html_report += '\t<div class="accordion-item">\n'
        html_report += f'\t\t<h2 class="accordion-header d-flex" id="heading{section.replace(" ", "")}">\n'
        html_report += f'\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{section}" aria-expanded="false" aria-controls="collapse{section}">{icons[section]}{' '.join(word[0].upper() + word[1:] for word in section.split())}</button></h2>\n'
        html_report += f'\t\t\t\t<div id="collapse{section}" class="accordion-collapse collapse" aria-labelledby="heading{section.replace(" ", "")}" data-bs-parent="#accordionPanel">\n'
        html_report += f'\t\t\t\t\t<div class="accordion-body bg-dark" style="word-break: break-all;">\n'

        if (section == "code_apis"):
            html_report += f'\t\t\t\t\t\t<div class="accordion" id="sub-accordion{section.replace(" ", "")}">\n'

            for sub_section, files in data[section].items():
                if (len(files) == 0):
                    empty = True
                else:
                    empty = False
                html_report += '\t\t\t\t\t\t\t<div class="accordion-item">\n'
                html_report += f'\t\t\t\t\t\t\t<h2 class="accordion-header" id="sub-heading{sub_section.replace(" ", "")}">\n'
                html_report += f'\t\t\t\t\t\t\t<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_section.replace(" ", "")}" aria-expanded="false" aria-controls="collapse{sub_section.replace(" ", "")}">{icons[sub_section]}{' '.join(word[0].upper() + word[1:] for word in sub_section.split())}</h2>\n'
                html_report += f'\t\t\t\t\t\t\t\t<div id="sub-collapse{sub_section.replace(" ", "")}" class="accordion-collapse collapse" aria-labelledby="sub-heading{sub_section.replace(" ", "")}" data-bs-parent="#sub-accordion{section.replace(" ", "")}">\n'
                html_report += '\t\t\t\t\t\t\t\t\t<div class="accordion-body bg-dark">\n'
                html_report += '\t\t\t\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col border border-white">File Name</div><div class="col-6 border border-white">Details</div><div class="col border border-white">Legitimate Use</div><div class="col border border-whites">Abuse</div></div>\n'
                for file_path, list_details in files.items():
                    file_name = file_path.split("/")[-1]
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t\t\t\t<div class="row"><div class="col border border-white" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="right">{file_name}</div><div class="col-6 border border-white">{html.escape(detail["suspicious"])}</div ><div class="col border border-white">{detail["legitimate"]}</div><div class="col border border-whites">{detail["abuse"]}</div></div>\n'
                html_report += '\t\t\t\t\t\t\t\t\t</div>\n'
                html_report += '\t\t\t\t\t\t\t\t\t</div>\n'
                html_report += '\t\t\t\t\t\t\t</div>\n'
                html_report += '\t\t\t\t\t\t\t</div>\n'
            html_report += '\t\t\t\t\t\t\t</div>\n'

        else:
            if (len(files) == 0):
                empty = True
            else:
                empty = False

            if (section == "permissions"):
                html_report += '\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col-6">Details</div><div class="col">Legitimate Use</div><div class="col">Abuse</div></div>\n'
                for file_path, list_details in files.items():
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t<div class="row"><div class="col-6 border border-white"">{html.escape(detail["suspicious"])}</div><div class="col border border-white"">{detail["legitimate"]}</div><div class="col border border-white"">{detail["abuse"]}</div></div>'
            else:
                html_report += '\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col border border border-white">File Name</div><div class="col-6 border border border-white">Details</div><div class="col border border border-white">Legitimate Use</div><div class="col border border border-white">Abuse</div></div>\n'
                
                for file_path, list_details in files.items():
                    file_name = file_path.split("/")[-1]
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t<div class="row"><div class="col border border border-white" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="top">{file_name}</div><div class="col-6 border border border-white">{html.escape(detail["suspicious"])}</div><div class="col border border border-white">{detail["legitimate"]}</div><div class="col border border border-white">{detail["abuse"]}</div></div>\n'
            html_report += '\t\t\t\t\t\t</div>\n'

        html_report += '\t\t\t\t\t</div>\n'
        html_report += '\t\t\t\t</div>\n'
        html_report += '\t</div>\n'

    html_report += '</div></div>'

    html_report += '</body></html>'

    html_report += "<script>let tooltipelements = document.querySelectorAll(\"[data-bs-toggle='tooltip']\");tooltipelements.forEach((el) => {new bootstrap.Tooltip(el);});</script>"
    
    if (empty):
        print("Error: No strings found. Please check if path is a decompiled apk and try again.")
    try:
        output_filename = os.path.join(new_directory_name, 'flagged_results.html')
        # output_filename = os.path.join(new_directory_name, f"{new_directory_name}.html")
        # current_time = get_current_time()
        # output_filename = os.path.join(new_directory_name, current_time + ".html")
        # print(new_directory_name) 
        # print(directory)
        with open(output_filename, 'w+') as flagged:
            flagged.write(html_report)
        print(f"Saved output as {output_filename}")
    except:
        print("error creating flagged_results.html. please check if path is a decompiled apk and try again.")


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

    identifier = get_identifier_from_path(args.path)
    new_directory_name = get_unique_directory_name(identifier, cwd)

    if args.subcommand == "decompile":
        dir_available = True
        try:
            if (not Path(args.output).is_dir()):
                dir_available = False
                print("Error: Output folder '"+args.output+"' not found. Please check the folder and try again.")
        except:
            if (args.output != None):
                dir_available = False
        if (os.path.isfile(args.path) and args.path.split(".")[-1] == "apk" and dir_available):
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
        
        # current_time = get_current_time()
        # with open(os.path.join(cwd, new_directory_name, current_time + ".json"), "r") as outfile:
        # with open(os.path.join(cwd, new_directory_name, f"{new_directory_name}.json"), "r") as outfile: 
        with open(os.path.join(cwd, new_directory_name, "flagged_files.json"), "r") as outfile:
            data = json.load(outfile)
        #fill="currentColor" 

        #icons svgs for each category stored in dictionary to embed into html file
        icons = {
            "code_apis": '<?xml version="1.0" encoding="UTF-8"?><svg style="color:white;" class="me-2" version="1.1" viewBox="0 0 2048 2048" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(1183,338)" d="m0 0h25l16 4 16 8 10 7 10 9 10 14 7 15 4 16v23l-3 15-48 168-59 207-59 206-59 207-59 206-56 196-6 17-9 16-11 12-7 6-13 8-16 6-14 3h-18l-18-4-16-7-12-9-8-7-11-15-7-14-4-16-1-8v-10l3-18 15-53 13-46 11-38 288-1008 15-53 6-16 9-14 9-10 8-7 13-8 12-5z"/><path fill="currentColor" transform="translate(500,596)" d="m0 0h25l14 3 16 7 14 10 11 11 10 15 6 16 3 14v19l-4 17-7 16-9 13-6 7h-2l-2 4-12 12h-2l-2 4h-2l-2 4-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-7 6-5 6-6 5-6 7-7 6-5 6-7 6-5 6-6 5-6 7-4 4h-2l-2 4-3 1-2 4-14 14 2 4 76 76v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2 100 100v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2v2l4 2 16 16 7 8 9 13 6 12 4 15 1 6v19l-4 17-7 16-10 14-9 9-10 7-16 8-15 4-7 1h-18l-15-3-16-7-11-7-12-11-342-342-9-12-6-10-6-18-2-13v-9l2-13 3-11 5-12 7-11 11-12 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 7-6 5-6 6-5 6-7 6-5 6-7 6-5 7-8h2l2-4h2l2-4h2l2-4h2l2-4h2l1-3 8-7 12-9 15-7z"/><path fill="currentColor" transform="translate(1522,596)" d="m0 0h26l16 4 16 8 12 9 10 10 6 5 6 7 6 5 7 8 103 103 6 5 6 7 6 5 6 7 6 5 6 7 6 5 7 8 139 139 6 5 7 8 12 12 9 13 6 12 5 19v23l-4 17-8 16-9 13-351 351-10 7-14 7-13 4-11 2h-17l-16-3-16-7-11-7-12-11-9-12-8-16-4-13-1-6v-21l4-17 7-16 10-13 9-10 275-275-1-4-284-284-9-13-7-15-4-16v-22l4-17 6-14 10-14 7-8 13-10 14-7 13-4z"/></svg>',
            "Messages": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(574,65)" d="m0 0h63l32 3 28 4 33 7 28 8 20 7 21 8 28 13 22 12 16 10 12 8 19 14 14 12 11 10 8 7 9 9 7 8 9 10 15 20 12 18 13 23 11 25 7 21 6 22 4 20 2 2v77h-2l-6 31-8 27-10 24-8 16-9 16-9 14-9 12-10 13-7 8-9 10-19 19-11 9-12 10h-2v20l3 115v51l-4 8-8 7-9 3h-9l-7-3-8-6-15-14-8-7-8-8-8-7-17-16-12-11-26-24-16-15-13-12h-7l-51 9-40 3-36 2-11 7-14 10-22 13-17 9-23 10-31 11-31 8-26 5-33 4-16 1h-35l-30-2-29-4h-6l-10 9-6 6h-2v2l-8 7-3 3h-2v2l-8 7-16 15-12 11-15 14-24 22-15 14-12 11-11 10-10 6-3 1h-10l-8-3-8-7-4-8-1-6 1-47 4-147v-13l-17-17-9-11-8-9-14-20-12-21-9-19-9-25-6-26-3-12v-60l5-22 5-19 6-18 9-20 8-15 12-19 14-18 7-8 12-13 10-10 11-9 9-8 17-12 15-10 21-12 29-14 32-12 20-32 11-14 9-12 9-9 7-8 6-7 8-7 11-10 11-9 16-12 16-11 25-15 23-12 19-9 35-13 35-10 27-6 32-5zm17 50-30 2-31 4-30 6-25 7-24 8-27 11-28 14-25 15-19 14-14 11-14 13-20 20-11 14-13 18-12 20-10 21-9 25-5 19-4 26-1 16v13l2 24 5 26 6 20 8 20 8 16 6 11 11 17 14 18 9 10 12 13 14 13 11 9 13 10 16 11 17 10 18 10 26 12 29 11 28 8 27 6 24 4 28 3 18 1h37l28-2 29-4 29-6 20-4 8 1 10 5 12 11 26 24 15 14 13 12 4 2v2l8 7 15 14h1v-24l-2-72v-37l3-9 7-8 14-11 11-9 10-9 21-21 11-14 8-10 14-22 15-30 9-27 5-22 2-12 1-13v-34l-2-17-5-24-5-16-7-19-10-21-14-23-10-13-13-16-8-8-1-2h-2l-2-4-13-12-11-9-17-13-15-10-20-12-23-12-23-10-34-12-30-8-26-5-23-3-20-2-20-1zm-395 220-16 8-13 7-12 8-18 13-14 13-8 7-9 9-9 11-10 13-13 21-10 21-6 18-5 21-2 16-1 21 1 17 4 22 6 21 10 23 9 16 13 19 12 14 12 13 8 7 9 10 3 6 1 4v29l-3 105v25l4-2 7-7 8-7 8-8 8-7 15-14 8-7 7-7 8-7 7-7 8-7 16-15 10-8 9-4 17 1 32 5 28 2h32l29-2 41-7 40-12 26-11 8-4-3-2-16-4-35-9-46-17-40-20-19-11-34-24-11-9-10-9-8-7-20-20-18-22-13-19-10-16-7-12-13-29-9-28-5-23-3-17-2-27v-13l2-28 5-29 1-8z"/><path fill="currentColor" transform="translate(391,331)" d="m0 0h15l16 3 13 5 11 7 10 9 10 11 8 15 4 12 2 13v13l-2 12-4 12-8 15-9 11-12 10-17 9-14 4-7 1h-17l-12-2-16-6-11-7-10-9-9-10-8-14-5-15-2-13v-9l2-13 4-13 7-14 10-13 11-9 13-8 14-5zm1 51-10 4-5 4-5 7-3 9v13l4 9 5 7 8 5 8 2h10l9-3 9-7 5-8 2-9-1-11-4-9-6-7-10-5-4-1z"/><path fill="currentColor" transform="translate(814,331)" d="m0 0h15l16 3 12 5 13 8 13 12 9 13 6 13 4 16v22l-4 16-8 16-4 6-9 10-8 7-14 8-14 5-12 2h-17l-15-3-16-7-11-8-10-9-8-11-8-16-3-11-1-7v-17l3-15 5-13 6-10 9-11 9-8 11-7 11-5 12-3zm1 51-10 4-8 7-5 10-1 5v9l3 9 7 9 10 6 5 1h11l10-4 8-7 4-6 2-6v-13l-4-10-7-8-9-5-4-1z"/><path fill="currentColor" transform="translate(602,331)" d="m0 0h16l15 3 13 5 11 7 10 8 10 12 7 12 5 14 2 11v19l-4 16-5 12-7 11-12 13-10 7-14 7-14 4-7 1h-18l-14-3-12-5-12-7-13-12-9-12-7-15-4-15-1-12 2-16 5-16 7-13 9-11 7-7 10-7 12-6 14-4zm2 51-9 3-7 5-6 10-2 6v12l4 10 7 8 6 4 8 2h10l9-3 8-6 6-9 2-7v-9l-3-10-6-8-9-6-6-2z"/></svg>',
            "Device Information and System Interaction": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(553,269)" d="m0 0h453l9 4 7 8 2 3v726l-9 10-5 2v2h-548l-4-4-6-5-4-8v-633l4-8 77-77 5-6 8-7 8-6zm16 46-7 6-7 8-54 54-6 5-1 226v364h483l1-7v-656z"/><path fill="currentColor" transform="translate(72)" d="m0 0h358l18 6 15 8 10 8 10 10 9 14 7 16 3 13 1 12v164l-1 9-6 10-6 4-7 2h-8l-8-3-6-5-4-7-1-4-1-171-2-11-6-12-5-6-9-6-13-4-114-1h-104l-118 1-13 4-11 8-7 9-4 8-2 9v756l3 11 6 10 4 5 11 7 10 4 7 1 304 1 7 2 9 8 3 6 1 10-4 10-5 6-5 3-4 1-76 1h-222l-18-1-16-4-16-7-14-10-11-11-10-14-7-16-4-13v-779l4-10 5-12 9-15 11-12 15-11 14-7z"/><path fill="currentColor" transform="translate(688,598)" d="m0 0h54l8 4 7 8 2 5v112l8-1h10l10 2 8 6 5 7 1 3v11l-4 8-4 5-7 4-5 1h-91l-8-3-7-7-3-6-1-10 4-11 7-6 6-3 18-1 6 1 1-83h-25l-6-3-6-5-4-7-1-4v-8l4-10 8-7z"/><path fill="currentColor" transform="translate(597,335)" d="m0 0h13l8 4 6 7 3 8v73l-4 10-7 7-8 3h-77l-8-4-6-7-3-7v-10l3-7 6-7 8-4 48-1 1-46 3-8 6-7z"/><path fill="currentColor" transform="translate(188,797)" d="m0 0h123l9 2 6 4 6 9 1 4v9l-5 10-7 6-4 2-10 1h-116l-9-2-8-7-5-10v-9l5-10 5-5z"/><path fill="currentColor" transform="translate(731,520)" d="m0 0h10l8 3 5 4 5 9 1 6v22l-4 10-5 6-5 3-12 2-9-3-8-7-4-9-1-11v-9l2-11 5-8 8-6z"/><path fill="currentColor" transform="translate(1023,1023)" d="m0 0"/><path fill="currentColor" transform="translate(434)" d="m0 0"/></svg>',
            "Network Communication" : '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(461)" d="m0 0h104v1l44 7 32 7 30 9 26 9 28 12 36 18 15 9 22 14 11 8 5-1 10-6 13-5 9-2 18-1 19 3 13 5 15 9 13 12 10 14 5 11 4 13 1 6v23l-4 17-5 11-5 8 1 5 14 21 15 25 15 29 10 22 7 17 12 36 9 36 6 32 3 21 2 2v106l-2 4-5 33-6 31-8 30-12 35-11 26-12 25-13 24-12 19-8 12-10 14-13 17-13 15-9 10-7 8-18 18-8 7-12 11-11 9-13 10-15 11-21 14-25 15-21 11-33 15-30 11-34 10-36 8-39 6-14 2h-93l-3-2-34-5-34-7-32-9-26-9-29-12-29-14-23-13-19-12-16-11-5 1-16 8-14 4-7 1h-20l-14-3-12-5-11-6-10-9-5-5-7-8-8-14-5-15-2-16 2-21 4-13 7-14 2-3-1-4-10-15-12-19-14-25-8-16-9-19-13-34-8-25-9-36-6-35-3-22-1-3v-93l2-10 5-35 7-33 7-25 11-33 10-24 12-25 11-21 13-22 10-14 6-5 5-2h7l9 4 5 5 4 8v7l-4 9-18 30-12 22-11 23-1 2h197l1-7 5-12 8-12 11-12 12-9 15-7 16-4 6-2 10-45 9-34 9-29 12-32 11-24 12-23 10-16 7-10-9 1-27 6-31 9-24 9-26 11-17 9-14 7-15 9-26 17-7 3h-9l-8-4-6-7-2-5v-9l4-8 9-8 11-7 19-12 25-14 29-14 30-12 33-11 32-8 31-6 30-4zm43 41-11 4-13 9-14 14-10 14-8 12-6 11-11 23-11 28-10 30-8 29-7 29-5 22 1 5 17 11 11 10 9 13 7 15 3 7 201 1 4-1-1-11-8-47-9-41-7-27-9-29-7-20-10-25-13-27-11-18-8-11-9-10-9-9-11-7-11-4zm90 7 4 7 10 15 9 16 13 27 9 23 9 26 10 33 11 45 9 48 6 39 6 1 256-1-9-20-11-22-16-27-12-18-5 1-16 5-7 1h-22l-16-4-11-5-10-6-11-9-11-14-7-14-4-12-2-20 2-17 4-13 2-6-9-7-19-12-21-12-19-10-27-12-34-12-25-7-26-6zm264 72-11 2-9 4-8 6-7 8-5 12-1 4v17l5 13 8 10 10 7 12 4h14l11-3 10-6 6-5 7-11 3-10v-16l-4-12-7-10-8-7-11-5zm-504 184-11 2-9 4-8 6-7 8-5 12-1 4v17l4 11 7 10 10 8 14 5h14l11-3 10-6 6-5 7-11 3-10v-16l-4-12-7-10-8-7-11-5zm-291 64-3 8-5 18-7 31-4 24-3 32-1 18v28l2 28 4 33 6 31 8 31 2 5h272l-1-20-3-44-2-56v-46l2-61-17-8-11-8-4-4h-2l-2-4-7-8-7-12-4-10-2-6zm375 0-4 10-8 16-8 10-2 4-4 2-10 8-16 8-15 5-1 7-2 58v33l1 39 3 54 3 34 210-1 6-16 10-16 13-13 13-8 8-4 17-5 1-1 2-40v-84l-2-44-4-51-1-5zm252 0v12l4 59 1 25v92l-1 40 19 10 10 8 9 9 7 11 6 12 4 9 4 1 208-1 4-11 8-32 5-27 3-24 2-25v-49l-3-34-5-32-9-39-4-13-1-1zm-26 264-14 3-10 6-9 9-6 12-2 10v9l3 11 4 8 9 10 10 6 10 3h14l13-4 10-7 8-9 4-8 2-11v-9l-3-12-7-12-8-7-12-6zm-586 64 3 9 17 34 13 22 13 20 1 2 7-1 13-4 15-2 17 1 16 4 16 8 9 7 8 7 10 14 6 12 4 14 1 5v24l-5 19-2 6 5 4 12 8 25 15 23 12 19 9 25 10 27 9 30 8 20 4h3l-1-4-7-10-9-15-12-23-9-20-13-35-10-32-7-26-8-36-7-37-6-39-1-3zm303 0 1 14 7 41 7 34 10 39 12 38 10 26 9 20 12 23 8 12 8 11 9 10 7 7 12 8 12 4h13l14-5 11-8 10-9 11-13 12-19 9-16 12-27 9-24 9-28 9-34 7-30 3-16-15-9-11-9-9-10-8-14-6-15-1-1zm368 0-5 12-8 15-8 10-11 10-14 8-13 5-16 4-9 42-8 31-9 30-7 20-10 25-8 18-10 19-11 18-7 10-1 3 11-2 23-5 28-8 28-10 26-11 24-12 24-14 23-15 19-14 11-9 13-11 10-9 8-8 6-5 7-8 9-9 9-11 11-13 14-19 10-15 13-21 13-24 12-26v-1zm-587 120-11 2-9 4-8 6-7 8-5 12-1 4v17l5 13 8 10 10 7 12 4h14l11-3 10-6 6-5 7-11 3-10v-17l-5-13-6-8-8-7-11-5z"/><path fill="currentColor" transform="translate(154,148)" d="m0 0h12l6 3 7 8 1 3v13l-6 8-6 4-3 1h-11l-8-5-4-5-3-9 2-9 4-6 6-5z"/></svg>',
            "Cryptography": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(124)" d="m0 0h25l15 8 10 10 7 14 1 4v18l-4 11-6 9-11 10-6 3h-2v10l-1 10h134l8 2 7 8 1 3v146l23-11 40-19 38-18 33-16 28-13 23-11 9-3-1-87-11-7-9-9-7-14-2-9v-8l3-12 5-10 8-9 11-7 7-3h25v2l5 1 10 6 9 9 7 14 1 5v16l-3 10-7 11-7 7-10 6h-2v87l23 11 22 10 17 9 6 6 1 3v8l-4 7-6 4h-10l-18-8-31-15-16-7-12 5-29 14-28 13-37 18-28 13-31 15-23 11-34 16-33 16-5 1 1 2 26 12 33 16 21 10 5-5 13-15 9-9 11-9 10-8 17-11 23-12 15-6 19-6 19-4 14-2 17-1h13l24 2 26 5 19 6 17 7 16 8 15 9 14 10 14 12 5 4 7 8 7 7 7 9 6-1 47-23 29-13-4-3-33-16-28-13-33-16-28-13-17-9-5-5-2-10 4-8 8-5h7l21 9 41 20 19 9 1-146 2-5 8-7 8-1h131l-1-19-10-6-10-10-7-14-2-8v-9l4-15 7-11 9-8 14-7h26l4 3 9 5 10 10 7 14 1 4v18l-4 12-8 10-8 7-7 4h-2v35l-3 9-6 6-3 1-135 1-3-1v75l182-1 5-8 7-9 8-6 8-4 7-2h17l12 4 9 6 7 7 7 12 2 5v25l-3 4-6 10-9 9-11 6-9 2h-17l-11-4-11-8-8-11-4-6h-170l-12-1 1 39 20 9 31 15 12 6 7 8v177l87-1 25-1 8-13 9-8 12-6 4-1h19l12 4 9 7 7 7 8 16v25l-2 1-5 10-9 10-9 6-9 3-5 1h-14l-10-3-10-6-8-8-6-10-1-2h-111l-1 175-3 5-8 6-29 14-28 13-2 1-1 38 183-1 7-12 8-8 8-5 9-3 6-1h9l10 2 12 6 8 7 7 11 4 8v26l-2 1-5 10-8 9-9 6-11 4-6 1h-11l-13-4-9-6-7-7-7-12-183-1v74h104l35 1 6 4 4 6 1 10v28l4 4 9 6 5 5 7 9 4 12v18l-5 13-6 8-7 7-12 6-5 2h-21l-16-8-9-9-7-12-3-12v-9l3-11 5-10 5-6 10-8 6-4 1-19h-138l-5-3-5-5-1-4-1-146-40 19-9 3-6-1-6-4-4-6v-9l4-7 8-5 39-19 28-13 35-17 22-10 1-338-16 7-29 14-20 9-14 7-6 2 12 25 7 19 5 19 3 16 2 18v32l-2 20-5 24-8 24-6 15-6 11-7 12-8 12-8 10-11 13-14 14-11 9-15 11-19 11-16 8-18 7-22 6-24 4-10 1 1 3-1 81 52-25 28-13 10-4 10 3 6 7 1 2v7l-4 8-8 5-26 12-16 8-40 19-11 5-1 9v79l6 2 11 8 7 10 4 9 1 5v16l-3 10-7 11-7 7-8 5-11 4h-20l-16-8-9-9-6-10-3-9-1-12 4-16 7-11 9-8 9-5 1-87-6-2-27-13-28-13-37-18-28-13-33-16-28-13-6-3-1 145-3 7-5 5-3 1-138 1v13l2 6 11 8 8 8 7 14 1 4v17l-3 10-7 11-10 9-10 5-5 2h-21l-16-8-9-9-7-12-2-7v-18l4-12 8-11 16-12v-19l1-19 4-6 6-5 6-1h134v-74l-183 1-9 14-9 8-11 5-9 2h-12l-13-4-10-7-9-10-6-13v-24h2l1-5 4-8 9-10 10-6 8-3 7-1h8l10 2 12 6 9 8 8 13h182v-37l-20-9-16-8-25-12-7-5-2-4-1-11v-166l-111 1-7 12-8 8-9 5-7 3-6 1h-14l-10-3-10-6-9-9-8-15v-24l8-15 8-9 12-7 7-2 12-1 11 2 9 4 6 4 5 4 7 10 4 6h91l19 1v-52l4-7 6-5 8-1 8 4 4 5 1 2v246l6 2 29 14 28 13 29 14 28 13 35 17 28 13 35 17 28 13 20 10v-84l-18-2-28-6-23-8-23-11-16-10-11-8-11-9-10-9-11-11-9-11-10-13-11-18-8-16-8-19-6-20-4-20-2-15-1-17v-11l2-24 5-26 10-30 13-27-9-3-22-11-23-11-30-14-1 1-1 36-4 6-5 4-9 1-7-4-5-6-1-7v-58l2-7 7-6 43-21 18-8 1-1v-37h-183l-2 6-7 10-11 8-9 4-5 1h-17l-12-4-8-6-8-8-8-15v-24l8-15 6-7 10-7 12-4h17l10 3 10 6 9 9 6 10v2l182-1 1-74-6 1h-125l-10-2-7-6-2-6-1-37-11-7-8-8-7-12-2-7-1-10 2-12 4-10 7-9 7-6zm8 31-5 3-3 4-2 5 1 7 3 5 6 4h9l6-4 4-6v-8l-4-7-5-3zm374 0-6 5-3 7 1 6 4 6 5 4h9l6-4 4-6v-8l-4-7-5-3zm376 0-6 4-4 7 1 7 4 6 5 4h9l6-4 4-6v-8l-4-7-5-3zm-842 183-6 4-4 9 2 8 4 5 8 3 6-1 6-4 3-5v-9l-3-5-6-5zm934 0-6 4-4 8 2 9 5 5 7 3 7-2 7-6 1-3v-8l-4-6-3-3-3-1zm-468 93-23 2-20 4-24 8-21 10-17 11-13 10-13 12-10 10-7 9-14 21-8 15-8 20-6 21-3 15-2 23v14l3 27 6 24 7 19 10 20 9 14 12 16 6 7h2l2 4 13 12 13 10 16 10 15 8 20 8 19 5 17 3 10 1h30l23-3 17-4 21-8 16-8 17-10 13-10 12-11 14-14 10-13 9-14 12-23 9-27 3-12 3-23v-33l-3-21-5-20-8-22-12-23-8-12-10-13-11-12-7-7-14-11-14-10-25-13-19-7-19-5-19-3-15-1zm-466 191-6 4-4 8 2 9 5 5 4 2h8l6-4 3-3 1-3v-9l-4-6-5-3zm937-1-7 3-5 6-1 7 3 7 5 5 2 1h9l6-4 3-3 1-3v-8l-4-7-5-3zm-934 284-7 3-4 4-2 9 3 7 6 5 2 1h8l6-4 4-6v-9l-4-6-4-3zm933 0-8 4-3 5-1 7 4 8 5 4 9 1 7-4 4-6v-8l-4-7-7-4zm-842 183-8 5-3 5-1 6 3 7 5 5 3 1h8l6-4 4-6v-8l-3-5-6-5zm375 0-6 3-5 6-1 7 3 7 5 5 2 1h9l6-4 3-3 1-3v-8l-4-7-5-3zm375 0-7 4-4 6-1 6 5 10 5 3h9l6-4 3-3 1-3v-8l-3-6-6-4z"/><path fill="currentColor" transform="translate(499,347)" d="m0 0h26l16 5 12 6 10 8 7 7 7 10 7 15 3 12v36l13 1 10 4 10 9 5 8 2 6v135l-4 10-6 8-8 6-7 3-5 1h-172l-11-4-10-9-5-8-2-5-1-8v-124l2-9 7-12 9-7 5-3 16-2 1-30 3-15 5-13 9-14 5-6 13-10 16-8zm3 31-11 4-11 8v2h-2l-6 9-4 12-1 10v23h89v-32l-3-10-6-10-8-8-14-7-3-1zm-72 99-2 1-1 6v118l1 4h168v-127l-4-2z"/><path fill="currentColor" transform="translate(507,481)" d="m0 0h8l13 3 11 6 7 6 7 11 4 12v16l-3 10-6 10-9 9-10 5-1 6v12l-3 8-5 5-6 3-8-1-6-5-4-8v-18l-9-6-8-7-6-7-5-11-2-9 1-14 4-10 6-10 9-8 12-6zm3 31-7 3-4 5-2 5 2 9 4 5 5 2h8l6-4 4-5v-9l-4-7-5-3z"/><path fill="currentColor" transform="translate(1023,496)" d="m0 0"/><path fill="currentColor" transform="translate(1023,781)" d="m0 0"/><path fill="currentColor" transform="translate(1023,212)" d="m0 0"/><path fill="currentColor" transform="translate(526)" d="m0 0"/><path fill="currentColor" transform="translate(150)" d="m0 0"/></svg>',
            "Content Providers and Databases": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 2048 2048" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(861,41)" d="m0 0h26l30 2 24 4 26 7 19 7 25 12 14 8 20 13 14 11 11 9 12 11 14 14 11 14 11 15 13 21 13 25 8 20 5 15v2l13-4 16-6 17-4 21-3 10-1h36l21 2 20 4 24 8 18 8 23 12 14 10 12 9 12 11 8 7 12 13 13 18 8 13 9 16 10 23 8 20 2 3 24 1 23 3 26 6 21 7 24 11 16 9 14 10 9 7 14 12 12 12 11 12 13 18 9 15 11 23 9 23 7 26 3 19 1 10v28l-4 33-5 21-8 22-12 25-11 18-9 12-10 13-11 12-10 10-13 10-16 11-15 9-25 12-21 7-27 6-22 3-36 2h-94l-19-1v19l-1 63 7 1 18 1 15 3 10 5 6 9 2 11v13l-2 20-5 19-10 23-8 14-12 16-17 17-13 10-15 9-20 8-18 4-25 3-45 2h-84v458l-1 21 98-1 4-1v-281l2-14 4-10 6-11 7-10 9-11 9-9 18-13 23-13 23-11 25-10 26-8 32-8 32-6 42-6 19-2 33-2 28-1h51l50 3 37 4 39 6 37 8 28 8 24 8 28 12 16 8 18 11 13 10 12 11 11 13 9 15 5 13 2 10v455l-1 57-2 18-5 13-7 11-7 9-9 10-13 11-17 11-22 12-21 9-34 12-48 12-35 7-38 5-35 3-36 2h-61l-51-3-43-5-32-5-32-7-30-8-34-12-24-11-16-8-19-13-14-12-11-12-9-14-5-11-4-16-2-28-1-112v-30h-85l-48-1-15-2-6-3-6-11-3-17-1-15-1-62v-306l1-112 1-13-2 1-117 1-1 1-1 477-1 30-3 16-4 8-4 3-9 2-10 1-23 1-110 1v69l-1 87-2 24-5 13-8 12-10 13-11 11-16 11-21 12-16 8-25 10-30 10-46 11-31 6-38 5-35 3-36 2h-60l-50-3-44-5-32-5-36-8-28-8-26-9-26-11-20-10-12-8-12-9-12-11-10-11-8-13-5-11-3-12-2-18-1-83-1-373v-45l3-15 8-16 7-11 8-10 8-9 11-9 16-11 18-10 19-9 28-11 23-7 36-9 32-6 35-5 27-3 34-2 32-1h38l40 2 36 3 45 6 36 7 35 9 30 10 26 11 20 10 17 11 10 8 13 12 9 10 10 15 6 13 2 12 1 26v262h100l1-452v-26h-114l-26-2-18-3-12-3-16-6-18-10-12-9-13-12-10-11-12-18-9-16-9-25-4-16-1-9v-11l3-16 5-9 7-6 8-2 33-3 1-9 1-74-16 1h-84l-28-2-29-6-21-7-24-11-16-10-14-10-10-9-8-7-10-9-7-7v-2h-2l-7-8-13-16-18-27-9-16-12-23-11-26-9-25-8-31-7-33-3-22-2-24v-26l4-37 6-28 5-16 9-24 9-19 12-21 12-17 9-12 7-9 13-15 13-13 10-8 13-10 21-14 22-12 17-8 16-6 32-9 20-4 20-1 7-2 8-16 10-23 8-16 10-17 12-17 8-10 7-8 9-10 18-18 14-11 14-10 18-11 22-12 24-10 26-8 27-5 15-2zm-3 62-26 3-23 5-24 9-23 12-19 12-13 10-15 14-15 15-8 10-9 13-12 21-8 16-8 19-8 22-9 17-3 3-6 2-31 2-29 4-32 8-24 10-19 10-19 13-14 11-13 12-4 4v2h-2l-7 8-10 13-13 20-12 23-10 26-6 20-4 24-1 10v36l3 28 4 23 7 27 11 33 11 25 9 17 14 22 13 17 12 14 11 11 8 7 14 11 21 12 18 8 17 5 21 3 19 1h84l6-2 1-1 1-149 2-21 4-21 7-19 12-22 14-18 11-10 14-10 19-10 15-5 20-3 15-1 41-1h339l30 1 25 2 17 4 15 6 12 6 13 9 11 10 5 5 8 9 9 14 8 15 6 17 3 12 2 17 1 22v144h114l25-1 27-3 16-4 15-5 19-9 17-11 13-10 10-9 14-16 12-18 8-16 8-21 4-16 3-24v-29l-2-19-4-17-6-17-11-22-9-14-11-14-16-16-13-10-20-12-21-9-15-5-17-4-11-1h-33l-14 1h-17l-12-12-6-12-6-21-5-17-8-18-11-21-12-17-11-12-9-9-18-13-15-9-21-9-16-5-14-3-16-2h-28l-22 3-21 5-15 6-20 9-16 8-10 4h-6l-5-6-8-7-5-8-5-14-7-26-10-25-12-25-10-17-10-14-13-15-11-11-14-11-15-11-21-12-15-7-18-7-17-5-21-4-21-2zm-26 491-22 1-15 3-14 6-11 9-8 9-7 11-5 11-3 16-1 30v274l1 3 7 1h541l4-1 1-159v-143l-3-22-5-12-9-12-10-10-13-8-16-5-7-1-41-1zm521 440m-660 1 2 5 10 17 16 17 12 9 15 7 18 4 10 1h135l20-1h17l5 1h143l9-1h24l9 1h136l19-2 17-8 14-10 10-9 9-11 5-7 4-9 1-4h-303l-193 1h-113zm-297 235-41 3-36 4-29 5-40 10-26 8-24 10-21 11-12 8-10 8-8 8-5 9v7l5 9 4 5 8 7 14 10 23 12 19 8 34 11 29 7 38 7 42 5 42 3h74l46-3 32-4 29-5 28-6 33-9 20-7 21-9 21-11 16-11 11-9 3-4 1-8-3-10-6-8-7-7-14-10-19-10-21-9-19-7-36-10-26-6-24-4-31-4-36-3-19-1zm1168 0-41 3-37 4-29 5-40 10-26 8-24 10-16 8-13 8-14 10v2l-4 2v2h-2l-6 9-1 3v7l5 10 11 11 14 10 12 7 27 12 36 12 43 10 37 6 35 4 28 2 31 1h35l42-2 35-3 39-6 35-7 29-8 27-9 25-11 16-9 20-14 10-10 1-2v-7l-7-14-12-12-10-7-14-8-25-11-31-11-35-9-18-4-37-6-41-4-34-2zm-1420 176-1 46v30l2 19 4 7 7 7 15 11 15 9 25 12 22 8 27 8 37 8 39 6 42 4 19 1h79l33-2 40-4 36-6 36-8 30-9 25-10 25-12 16-10 13-10 4-6 1-9 1-25v-62l-9 2-17 7-15 7-28 10-28 8-41 9-34 6-47 5-25 2-20 1h-75l-31-2-39-4-29-4-36-7-32-8-36-12-21-9-28-14zm1166 0 1 89 2 11 5 5 11 10 17 11 21 11 20 8 30 10 34 8 35 6 31 4 39 3 33 1h37l44-2 42-4 37-6 36-8 30-9 21-8 20-9 15-8 18-12 10-9 2-3 1-6 1-23v-68l-9 2-18 8-17 8-35 12-36 9-33 7-33 5-51 5-33 2h-74l-31-2-39-4-30-4-40-8-30-8-36-12-23-10-16-8-7-4zm-1166 177-1 40v18l1 17 3 9 9 9 12 9 16 10 25 12 25 9 19 6 34 8 36 6 33 4 28 2 23 1h67l36-2 39-4 36-6 31-7 25-7 28-10 26-12 15-8 16-11 7-6 1-3 1-14 1-28v-37l-1-2-9 2-31 14-37 13-23 6-42 9-39 6-37 4-49 3h-68l-35-2-45-5-33-5-36-8-29-8-33-11-25-11-16-9zm1166 0 1 71 2 12 5 6 11 9 13 9 16 9 18 8 25 9 27 8 31 7 45 7 31 3 39 2h67l37-2 37-4 36-6 32-7 33-10 21-8 26-12 17-10 14-10 6-6 2-10 1-18v-55l-11 3-20 9-19 8-28 10-27 7-43 9-35 5-38 4-27 2-22 1h-66l-35-2-46-5-38-6-30-7-26-7-26-8-28-11-19-10-7-4zm-1166 161-1 19v49l2 10 4 7 8 9 12 9 15 9 21 10 24 9 26 8 29 7 27 5 29 4 33 3 35 2h58l40-2 33-3 27-4 36-7 28-7 36-12 18-8 16-8 14-8 14-12 5-6 2-6 1-9 1-22v-36l-2-7-13 4-27 12-34 12-23 6-45 10-39 6-37 4-44 3-32 1h-20l-28-1-48-4-38-5-30-5-37-9-31-9-25-9-26-12-12-7zm1166 0-1 41v23l2 13 5 10 12 11 19 12 16 8 24 10 31 10 28 7 32 6 29 4 33 3 36 2h56l41-2 33-3 33-5 30-6 28-7 33-11 27-12 20-11 13-10 8-8 3-6 2-14 1-17v-32l-1-12-5-1-16 6-17 8-38 14-26 7-36 8-30 5-42 5-38 3-16 1-32 1h-18l-29-1-48-4-46-6-31-6-36-9-32-10-24-10-25-12-5-3z"/></svg>',
            "Audio and Video": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(428)" d="m0 0h529l15 5 14 7 14 11 8 9 8 14 6 14 2 5v433l-2 2-4 11-6 12-9 12-7 7-10 7-16 8-16 4-10 1h-118v155l-3 17-5 12-6 11-11 13-11 9-15 8-13 4-14 2-86 1-1 149-2 18-4 12-8 15-9 11-10 9-14 8-12 5-8 3h-528l-18-7-11-6-9-7-11-11-7-11-6-12-4-12v-431h2l1-7 5-13 9-14 5-6h2l2-4 11-8 11-6 10-4 15-3h91v-151l2-15 4-13 7-14 9-11 2-3h2v-2l13-10 16-8 11-3 6-1 124-1 2-1v-41l1-116 3-14 7-16 8-12 7-8h2v-2l14-10 13-6zm21 33-18 2-12 6-7 5v2h-2l-7 10-5 12-1 6v155h262l1-1v-164h298l-1 321-4 13-5 9-7 8-11 7-13 4-12 1-14-3-10-5-10-9-6-9-5-12-1-7v-9l3-13 6-11 8-9 11-7 13-4h16l8 1v-167h-230v66h34l26 1 14 3 16 7 13 9 10 10 9 14 6 14 3 15 1 224h118l11-2 10-4 11-8 6-7 6-12 2-10v-410l-4-13-6-10-5-6-10-7-10-4-4-1-23-1zm245 66v32h230v-31l-4-1zm-455 166-13 4-9 6-9 9-8 16-1 6-1 43v331l1 39 3 10 7 12 8 8 10 6 9 3 5 1h507l13-3 10-5 10-9 7-11 3-9 1-8v-406l-2-10-7-14-10-10-14-7-8-2zm664 99-6 4-4 6-1 8 4 8 6 5 8 1 7-3 5-5 2-4v-9l-3-5-6-5-2-1zm-802 131-26 1-8 2-9 4-8 6-7 7-8 16-1 4-1 61v342l1 13 5 14 7 9 7 7 14 7 9 2h509l12-3 10-6 9-8 7-11 3-10 1-7v-152l-387-1-17-3-16-7-10-7-10-9-8-10-8-16-3-8-2-10-1-16v-211z"/><path fill="currentColor" transform="translate(363,353)" d="m0 0 4 1 19 9 16 8 19 10 21 10 19 10 21 10 120 60 19 10 54 27 5 3-1 3-23 11-19 10-234 117-19 9-19 10h-2l-1-120v-96zm34 55v208l6-2 114-57 17-9 23-11 19-10 29-14v-2l-22-11-19-10-62-31-19-9-19-10-64-32z"/><path fill="currentColor" transform="translate(149,858)" d="m0 0h93l6 1v32h345l2 2v31l-1 1h-346v33l-93 1-7-1v-33h-82l-1-1v-32l1-1h82v-32zm33 34v32h31l1-7v-24l-8-1z"/><path fill="currentColor" transform="translate(256,297)" d="m0 0h74l1 1v31l-3 2h-63v130l-2 2h-32l-1-10v-123l2-11 5-9 7-7z"/><path fill="currentColor" transform="translate(430,131)" d="m0 0h196l2 1v33l-193 1-6-1v-33z"/><path fill="currentColor" transform="translate(430,65)" d="m0 0h179l18 1 1 1v31l-1 1-192 1-6-1-1-3v-12l1-18z"/><path fill="currentColor" transform="translate(231,495)" d="m0 0h33l1 2v31l-2 1h-32l-1-1v-32z"/><path fill="currentColor" transform="translate(66,627)" d="m0 0h33l1 2v29l-2 3h-32l-1-1v-32z"/><path fill="currentColor" transform="translate(66,561)" d="m0 0h33l1 7v24l-3 3h-31l-1-1v-32z"/><path fill="currentColor" transform="translate(66,693)" d="m0 0h33l1 7v24l-2 3h-32l-1-1v-32z"/><path fill="currentColor" transform="translate(231,561)" d="m0 0h33l1 1v31l-2 2h-32l-1-32z"/><path fill="currentColor" transform="translate(726,660)" d="m0 0h33l1 1v32l-1 1h-32l-1-1z"/><path fill="currentColor" transform="translate(726,528)" d="m0 0h33l1 1v32l-1 1h-32l-1-1z"/><path fill="currentColor" transform="translate(726,594)" d="m0 0h33l1 1v32l-2 1h-31l-1-1z"/><path fill="currentColor" transform="translate(1023,60)" d="m0 0"/><path fill="currentColor" transform="translate(62,1023)" d="m0 0 2 1z"/></svg>',
            "System and Reflection": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(82,31)" d="m0 0h571l16 2 12 5 10 8 8 11 4 10 1 5v311h237l16 2 12 5 10 8 8 11 4 10 1 5v527l-3 11-6 11-10 10-9 5-9 3-7 1h-586l-13-3-11-7-9-9-6-10-3-10-1-11v-142h-180l-7-4-4-7-1-12v-91l3-6 2-3h2v-2l4-3 4-1h177l-1-30-244-1-13-3-10-6-6-5-6-8-5-10-2-7-1-11v-510l2-14 7-14 9-10 14-8 8-2zm-3 33-7 2-5 5-2 3-1 9v76l7 1 600-1v-84l-4-7-5-3-6-1zm-14 128-1 5v396l2 7 7 6 2 1h52v-415zm96 0-1 3v412h159v-63l-52-1-6-3-4-6v-12l5-7 3-2 7-1 47-1v-31l-53-1-6-4-3-6v-10l4-7 4-3 7-1 47-1 2-25 1-5-1-1-55-1-6-4-3-6v-10l4-7 5-3 7-1 398-1v-191zm206 224-7 2-6 7-2 10v76l17 1 590-1v-84l-4-7-5-3-6-1zm-15 128v127h31l1-49 2-12 4-9 6-9 9-8 12-6 16-2 16 3 11 6 9 8 6 10 4 12v18l-5 14-9 12 13 12 8 7 10 9 11 9 3 3h2v2l11 9 4 4 5-1 11-6 7-2 10-1 14 2 14 7 9 8 7 12 3 10v19l-5 13-8 11-8 6-10 5-8 2h-17l-10-3-10-6-5-4-6-8-5-8-5 3-15 13-11 10-8 7-14 12-10 9-11 9-13 12-11 9-1 7-1 56-3 5-5 4-3 1h-8l-8-4-3-5-1-7-1-111h-30l-1 5v140l2 7 7 6 2 1h585l7-4 4-7v-404zm74 65-7 5-1 4 14 13 6 5 5-1 4-6v-10l-4-7-5-3zm-9 52-1 6-1 26-4 6-3 3-3 1-245 1v63l239 1 9 2 6 7 1 2 1 32 5-2 9-9 8-7 10-9 11-9 14-13 8-7 21-18-2-4-14-13-11-9-12-11-8-7-14-12-15-13-8-7zm141 75-7 3-5 5-2 9 3 7 4 5 4 2h10l8-6 2-4v-10l-3-5-6-5z"/><path fill="currentColor" transform="translate(368,255)" d="m0 0h251l11 1 7 5 3 6v9l-3 6-7 6h-268l-6-4-4-6v-11l4-7 5-4z"/><path fill="currentColor" transform="translate(814,831)" d="m0 0 16 2 14 7 10 9 6 10 4 12v18l-5 14-6 8-4 5-12 8-13 4h-16l-13-4-9-6-6-5-7-10-4-10-1-4v-19l4-11 6-10 8-8 10-6 10-3zm0 33-7 3-5 5-2 9 3 7 4 5 4 2h9l7-4 3-4 1-3v-9l-3-5-6-5z"/><path fill="currentColor" transform="translate(678,576)" d="m0 0h19l10 3 12 7 9 10 6 12 2 7v18l-5 14-7 9-5 5-5 4-10 5-9 2h-15l-13-4-9-6-5-4-6-8-5-10-2-7v-19l4-11 6-10 8-8 10-6zm8 32-7 3-5 5-2 5 1 8 6 8 4 2h10l8-6 2-4v-10l-4-6-5-4z"/><path fill="currentColor" transform="translate(558,831)" d="m0 0 16 2 14 7 9 8 7 11 4 13v17l-5 14-6 8-4 5-12 8-14 4h-15l-13-4-11-7-8-9-6-12-2-7-1-9 2-14 8-16 9-9 10-6 10-3zm0 33-8 3-4 5-2 5 1 8 6 8 4 2h10l7-5 3-6v-9l-3-5-6-5z"/><path fill="currentColor" transform="translate(870,704)" d="m0 0h19l10 3 12 7 9 10 6 12 2 7v18l-5 14-6 8-4 5-10 7-11 4-5 1h-16l-12-4-9-6-6-5-7-10-4-10-1-4v-18l4-12 7-11 7-7 10-6zm4 33-6 4-3 5-1 7 3 7 4 5 4 2h9l7-4 3-4 1-3v-9l-4-6-5-4z"/><path fill="currentColor" transform="translate(806,576)" d="m0 0h19l10 3 12 7 7 7 6 10 4 12v18l-5 14-7 9-5 5-10 7-14 4h-15l-13-4-9-6-5-4-6-8-5-10-2-7v-18l3-10 6-11 9-9 10-6zm8 32-7 3-5 5-2 5 1 8 6 8 4 2h10l8-6 2-4v-10l-4-6-5-4z"/><path fill="currentColor" transform="translate(274,319)" d="m0 0h156l10 2 5 5 3 5v10l-5 8-5 3h-172l-6-4-4-7v-10l4-7 6-4z"/><path fill="currentColor" transform="translate(495,319)" d="m0 0h127l10 2 5 5 3 5v10l-4 6-6 5h-140l-6-4-4-6v-12l6-8 3-2z"/><path fill="currentColor" transform="translate(522,576)" d="m0 0h11l6 3 4 5 1 3v74l-4 6-5 4-3 1h-8l-8-4-4-6-1-4v-68l3-8 6-5z"/><path fill="currentColor" transform="translate(910,831)" d="m0 0 10 2 7 7 1 3v74l-4 7-8 4h-8l-8-4-4-6-1-5v-67l3-7 5-5z"/><path fill="currentColor" transform="translate(906,576)" d="m0 0h11l6 3 4 5 1 2v75l-4 6-5 4-3 1h-8l-6-3-6-7-1-5v-67l3-8 6-5z"/><path fill="currentColor" transform="translate(650,704)" d="m0 0h11l7 4 4 6v75l-4 6-5 4-2 1h-9l-6-3-6-7-1-5v-66l3-9 6-5z"/><path fill="currentColor" transform="translate(586,576)" d="m0 0h11l6 3 4 5 1 3v74l-6 8-5 3h-9l-8-4-4-6-1-6v-66l3-8 6-5z"/><path fill="currentColor" transform="translate(718,703)" d="m0 0 8 1 8 7 2 4v74l-3 5-6 5-3 1h-7l-8-3-5-6-1-6v-66l2-7 4-5 5-3z"/><path fill="currentColor" transform="translate(650,832)" d="m0 0h11l7 4 4 6v75l-4 6-5 4-3 1h-8l-6-3-6-7-1-6v-65l3-9 6-5z"/><path fill="currentColor" transform="translate(778,704)" d="m0 0h11l7 4 3 4 1 3v74l-6 8-6 3h-8l-8-4-4-6-1-6v-65l3-9 6-5z"/><path fill="currentColor" transform="translate(718,831)" d="m0 0 10 2 7 8 1 2v74l-4 6-5 4-3 1h-8l-8-4-4-6-1-6v-65l2-7 4-5 5-3z"/><path fill="currentColor" transform="translate(462,831)" d="m0 0 8 1 8 7 2 4v74l-4 6-5 4-3 1h-8l-8-4-4-6-1-6v-64l3-9 8-7z"/><path fill="currentColor" transform="translate(272,255)" d="m0 0h31l9 2 5 5 3 5v10l-5 8-6 3h-43l-6-4-4-7v-10l4-7 5-4z"/><path fill="currentColor" transform="translate(106,96)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-8-4-4-6-1-8 3-7 5-5z"/><path fill="currentColor" transform="translate(394,448)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-6-3-6-7-1-8 4-9z"/><path fill="currentColor" transform="translate(522,448)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-6-3-6-7-1-8 3-7 5-5z"/><path fill="currentColor" transform="translate(458,448)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-6-3-6-7-1-8 3-7 5-5z"/><path fill="currentColor" transform="translate(202,256)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-6-3-6-7-1-8 4-9z"/><path fill="currentColor" transform="translate(170,96)" d="m0 0h11l7 4 4 7v10l-4 6-5 4-3 1h-8l-6-3-6-7-1-8 3-7 5-5z"/><path fill="currentColor" transform="translate(202,512)" d="m0 0h11l7 4 4 7v10l-6 8-6 3h-8l-6-3-6-7-1-8 4-9z"/><path fill="currentColor" transform="translate(234,96)" d="m0 0h11l7 4 4 7v10l-6 8-6 3h-8l-6-3-6-7-1-8 3-7 5-5z"/><path fill="currentColor" transform="translate(202,448)" d="m0 0h11l5 3 5 6 1 2v10l-6 8-6 3h-8l-6-3-6-7-1-8 4-9z"/><path fill="currentColor" transform="translate(202,384)" d="m0 0h11l5 3 5 6 1 2v10l-6 8-6 3h-8l-6-3-6-7-1-8 4-9z"/><path fill="currentColor" transform="translate(202,320)" d="m0 0h11l5 3 5 6 1 2v10l-6 8-6 3h-8l-6-3-6-7-1-8 4-9z"/></svg>',
            "User Interface": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(154,47)" d="m0 0h708l28 1 16 3 13 5 13 7 9 7 10 9 8 10 8 14 6 15 3 17v598l-2 13-4 13-8 16-10 14-10 10-15 10-13 6-13 4-12 2-68 1h-17l-21-1-9-6-5-10 1-10 6-9 8-4 100-1 14-3 12-6 11-9 8-11 5-13 1-6 1-484h-848v474l2 16 5 13 8 11 9 8 14 7 7 2 9 1 185 1 7 3 5 5 4 8v7l-5 10-5 4-5 2-18 1h-108l-68-1-20-4-16-7-13-9-12-11-8-10-6-10-7-15-4-20-1-48v-527l1-28 4-17 5-12 9-16 15-16 12-9 16-8 17-5 8-1zm-9 40-16 2-12 5-11 8-9 10-6 12-3 10-1 12v63h849v-73l-3-11-7-14-10-11-11-7-15-5-9-1z"/><path fill="currentColor" transform="translate(481,394)" d="m0 0h8l14 3 10 5 10 8 8 11 5 12 2 10v80l7-1h12l13 3 11 6 5 2 10-6 10-4 6-1h12l12 3 12 6 2 2 4-1 10-6 8-3 6-1h14l12 3 11 6 11 10 7 11 4 10 1 5v195l-3 21-5 17-13 34-5 24-1 8 14 8 9 9 7 14 1 4v61l-6 9-6 4-10 1-7-2-7-6-3-7-1-16v-40h-276l-1 54-3 8-4 5-6 3-10 1-8-3-7-8-2-6v-54l3-12 6-10 6-7 11-7 5-3-3-17-6-21-8-18-8-14-10-13-9-11-8-13-5-12-3-15v-123l4-15 6-11 11-12 10-7 12-5 9-2h11l12 2v-114l2-12 5-12 7-10 8-7 10-6 10-3zm0 40-7 4-2 3-1 5-1 237-3 8-6 5-4 2h-12l-7-4-5-8-1-4-1-77-8-7-3-1h-9l-8 4-6 7-1 3v120l4 11 7 11 8 9 13 19 12 23 7 18 6 24 3 18 1 1h214l4-26 5-19 15-40 3-17v-192l-3-5-5-4h-9l-5 3-4 6-1 8-1 35-6 9-6 3-8 1-9-3-5-5-3-6-1-12v-27l-3-7-6-5h-9l-6 4-3 6-1 36-2 8-5 7-6 3-8 1-9-3-4-2-2-4-2-5-1-40-4-8-5-3h-9l-7 6-2 5-1 38-3 7-5 6-9 3-9-1-6-4-4-5-2-5-1-168-5-8-6-2z"/><path fill="currentColor" transform="translate(475,128)" d="m0 0h52l23 1 8 5 5 7 1 3v9l-6 10-7 4-5 1h-362l-7-3-5-5-3-4-1-3v-10l5-8 8-6z"/><path fill="currentColor" transform="translate(344,427)" d="m0 0h26l10 1 8 5 4 5 2 6-1 9-3 6-5 5-7 3h-43l-7-4-6-7-1-3v-11l3-7h2l2-4 6-3z"/><path fill="currentColor" transform="translate(603,356)" d="m0 0h12l6 3 6 7 2 5v9l-4 8-9 7-27 15-6 2-9-1-7-4-4-5-3-8 2-10 4-6 5-4 26-15z"/><path fill="currentColor" transform="translate(478,284)" d="m0 0h13l9 6 3 5 1 4v43l-5 9-6 4-4 1h-9l-7-3-7-8-2-11v-27l2-12 4-6z"/><path fill="currentColor" transform="translate(359,355)" d="m0 0 9 2 20 11 14 9 4 5 2 4v12l-6 9-6 4-10 1-10-4-23-13-9-7-4-8v-9l4-8 7-6z"/><path fill="currentColor" transform="translate(599,427)" d="m0 0h26l12 2 8 7 3 5v13l-6 8-6 4-3 1h-43l-6-3-7-8-1-3v-12l5-8 5-4z"/><path fill="currentColor" transform="translate(551,303)" d="m0 0h10l8 4 6 7 1 3v11l-8 16-7 11-5 9-6 5-5 2h-11l-8-5-5-8-1-3v-7l4-9 13-23 6-8 5-4z"/><path fill="currentColor" transform="translate(407,303)" d="m0 0h11l8 5 5 6 14 25 4 9v8l-4 8-6 5-5 2h-10l-6-3-8-9-13-23-4-8v-11l5-8 5-4z"/><path fill="currentColor" transform="translate(677,128)" d="m0 0h8l8 2 6 4 5 8 1 9-3 7-4 6-10 4h-14l-8-3-7-8-2-6 1-9 4-7 5-4 4-2z"/><path fill="currentColor" transform="translate(753,128)" d="m0 0h8l8 2 8 7 3 6v11l-6 9-7 4-4 1h-13l-7-2-6-5-4-8v-9l3-7 8-7z"/><path fill="currentColor" transform="translate(829,128)" d="m0 0 13 1 8 5 5 7 1 3v8l-4 8-6 6-7 2h-14l-8-3-7-8-2-9 2-8 5-7 7-4z"/></svg>',
            "Accessibility and System Settings": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(275)" d="m0 0h82l9 7 6 8 2 6v46l8 1 17 5 20 8 21 10 10 6 4-1 28-28 10-5 10-1 9 3 8 6 5 4 6 7 6 5 6 7 6 5 6 7 6 5 8 11 2 6v10l-4 9-7 9h-2l-2 4h-2v2h-2v2h-2v2h-2v2l-8 7-4 4 1 5 8 14 9 19 9 25 5 16 8-1 11-7 5-2h89l10 4 8 7 5 9 1 5 1 57 27 7 27 10 27 13 17 10 4-1 37-37 12-6h13l9 4 10 8 47 47 8 10 4 11v7l-4 11-9 10-7 8-10 10h-2l-2 4-8 7-2 3h-2l5 10 8 14 11 23 9 24 7 25 1 6h56l8 2 8 5 6 7 4 6v98l-3 3-7 8-8 5-11 2h-53l-2 11-5 17-5 15-9 21-11 22-8 13 1 4 37 37 5 8 2 7v7l-4 11-8 10-49 49h-2v2l-9 6-10 3-10-1-8-4-10-9-31-31-4 1-22 12-21 10-18 7-27 8-10 2v57l-3 9-4 6-8 7-5 1v2h-95l-11-7-7-9-3-9v-57l-14-3-20-6-28-11-20-10-15-9-5-1-8 8-5 6-7 6-1 2h-2l-2 4h-2l-2 4h-2l-2 4-11 8-9 3h-7l-11-4-13-11-18-18v-2l-3-1-5-6-6-5-6-7-4-3v-2h-2l-8-10-4-9v-13l5-10 9-10 29-29h2l-3-7-13-24-10-22-8-22-7-27-56-1-8-2-9-6-5-6-4-10v-89l6-12 4-5v-7l-36-12-24-11-11-6-5-3-5 2-7 7-1 2h-2l-2 4h-2v2h-2v2h-2v2l-8 7-5 4-8 3h-10l-9-4-10-9-41-41-5-10-1-9 3-10 7-9 25-25-1-5-11-20-10-24-5-15-3-11v-4h-45l-9-3-9-8-4-7v-80l7-10 5-4 6-3 5-1h44l2-11 9-27 11-24 8-13-1-5-27-27-5-8-2-7 1-10 4-8 9-10 40-40 9-5 11-1 9 3 6 4 28 28 5-1 20-11 21-9 18-6 11-3h4v-43l3-11 8-9zm15 30-1 1-1 45-5 10-5 5-10 4-27 8-22 9-22 12-10 5-3 1h-9l-9-4-11-9-9-9-5-6h-2l-2-4-2-2-5 1-9 9v2h-2l-4 4v2h-2v2h-2l-6 7-9 9 2 4 24 24 6 9 2 6v9l-4 10-12 22-6 13-8 22-6 21-5 8v2l-10 5-4 1-43 1-2 2v52l45 1 10 4 7 8 4 10 7 24 7 18 11 22 8 14 1 4v9l-4 10-11 12-16 16-3 2 1 5 9 9h2l2 4h2l2 4h2l2 4h2l2 4h2l2 4 7 6 7-6 9-9 5-6 8-7 8-5 5-2h8l11 4 21 12 20 9 18 6 21 6 6 4 5 6 3 8 1 11 38 1 4-2 6-23 10-28 7-16 15-27 2-3-1-5-36-36h-31l-19-4-16-6-16-9-11-9-3-3h-2v-2h-2l-2-4-7-8-8-13-6-12-5-16-3-17v-19l3-19 5-15 7-14 6-5h11l6 4 3 5 1 6-4 11-5 13-3 17v14l3 15 5 13 6 11 9 11 10 9 13 8 12 5 14 3h21l5-5 9-10 22-22v-2l4-2v-2l4-2v-2l4-2v-2l4-2 13-13 8-6v-20l-3-15-6-15-9-14-11-11-15-10-15-6-16-3h-16l-16 3-7 2h-8l-6-4-3-4-1-9 4-8 10-5 11-3 17-2h14l21 3 17 6 17 9 11 8 11 10 10 13 9 16 6 16 4 20v30l37 37 5-1 21-12 23-11 25-9 22-6 6-2v-41l-12-1-10-5-6-7-5-15-6-20-10-24-9-17-7-14-1-9 4-11 7-8 23-23-1-5-34-34-5 1-7 8-18 18-8 5-6 2h-8l-11-4-21-12-21-9-18-6-15-4-10-5-6-7-3-8-1-45zm309 249-1 59-4 9-6 7-11 5-32 9-25 10-16 8-25 14-6 2h-12l-9-4-8-7-33-33-5 2-30 30v2l-4 2v2l-4 2v2l-4 2-7 7 6 7 34 34 5 11v13l-4 9-12 21-10 21-8 21-9 32-6 11-7 6-9 3-58 1v74l58 1 12 5 6 7 5 12 7 25 7 20 14 29 12 21 2 6v12l-4 9-5 6v2h-2l-7 8-15 15-2 1v2h-2v2h-2v2l-4 2-2 3h2l2 4 48 48 7-6 33-33 12-6h11l11 4 17 10 16 8 15 7 27 9 22 6 10 6 6 9 2 5 1 59 44 1h29l1-2 1-57 4-10 5-6 12-6 29-8 26-10 17-8 24-14 8-3h11l10 4 10 9h2l2 4h2l2 4 16 16h2l2 4 3 3 4-1 50-50-6-7-32-32-5-8-2-7v-9l4-10 14-25 9-19 8-22 9-32 6-10 9-6 5-2 59-1v-74h-47l-12-1-9-4-5-4-5-8-6-19-6-20-8-21-8-17-13-23-4-10v-10l4-10 11-12 30-30-6-7-44-44-3-1-8 7-1 3-3 1-5 5v2l-4 2v2l-3 1-5 6-8 7-9 6-5 2h-12l-10-4-21-12-25-12-33-11-21-6-8-6-5-8-2-6-1-58z"/><path fill="currentColor" transform="translate(628,443)" d="m0 0h17l26 3 21 5 22 8 23 12 14 10 10 8 10 9 10 10 11 14 7 10 9 16 7 15 8 24 4 20 2 20v19l-2 20-5 23-7 20-11 23-14 21-12 14-16 16-20 15-16 9-19 9-18 6-23 5-20 2h-21l-25-3-20-5-17-6-23-11-15-10-13-10-12-11-3-6v-8l4-7 6-4h9l6 3 10 9 14 10 15 9 15 7 18 6 21 4 11 1h19l18-2 22-5 20-8 17-9 14-10 15-13 10-11 10-14 8-13 8-19 5-16 4-20 1-10v-21l-2-17-5-21-7-19-10-19-10-14-12-14-11-10-15-11-18-10-20-8-19-5-13-2-21-1-18 1-25 5-17 6-16 8-12 7-12 9-10 9-11 11-11 15-10 17-8 19-6 21-3 21v24l3 21 6 21 4 11v9l-6 8-7 3-8-1-6-4-6-12-5-15-5-23-2-16v-28l3-22 7-27 9-21 11-20 12-16 11-13 10-10 11-9 15-11 18-10 18-8 19-6 20-4z"/><path fill="currentColor" transform="translate(623,519)" d="m0 0h26l16 3 16 5 19 10 13 10 14 14 9 13 8 15 5 14 3 12 2 23-3 24-5 16-7 15-9 14-7 9h-2l-2 4-13 11-15 9-13 6-17 5-12 2-15 1-19-2-16-4-16-7-14-8-11-9-12-12-10-14-8-15-6-18-3-16v-25l3-17 6-18 8-15 12-16 12-12 14-10 17-9 15-5zm3 31-15 3-13 5-12 7-11 10-5 5-6 8-6 10-6 16-2 11v23l4 16 5 12 7 11 11 13 15 11 15 7 17 4h24l14-3 16-7 11-7 12-11 7-9 5-9 5-11 3-11 2-19-2-17-5-16-8-15-11-13-12-10-15-8-16-5-8-1z"/><path fill="currentColor" transform="translate(586,1023)" d="m0 0"/><path fill="currentColor" transform="translate(358)" d="m0 0"/></svg>',
            "File and Data Handling": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(51,319)" d="m0 0h142l8 3 15 14 30 30 210 1 14 1 8 7 2 4v314l-4 6-5 4-2 1h-426l-7-4-4-7-1-12v-346l2-7 5-5 4-3zm13 33v319h384l-1-271-212-1-6-4-10-9-16-16-5-6-7-6-5-5-3-1z"/><path fill="currentColor" transform="translate(688,95)" d="m0 0h207l9 2 11 11 9 11 11 13 9 11 11 13 11 14 10 11 11 14 5 8v266l-4 6-5 4-2 1h-298l-7-4-4-7-1-12v-346l2-7 7-7zm17 33-1 3v316h255v-223l-68-1-7-4-3-6-1-9-1-76zm207 30v33h28l-3-5-12-14-9-11z"/><path fill="currentColor" transform="translate(690,639)" d="m0 0h126l9 3 15 14 30 30 104 1 10 2 7 8 1 2v218l-4 6-5 4-2 1h-298l-7-4-4-7-1-12v-250l2-7 4-5 5-3zm15 33-1 5v218h255v-175l-100-1-6-4-10-9-12-12-7-8-12-12-5-2z"/><path fill="currentColor" transform="translate(575,239)" d="m0 0h45l10 1 7 5 3 6v10l-5 8-5 3h-38l1 6-1 473h30l10 2 5 4 3 6v10l-5 8-6 3h-58l-7-4-4-7-1-12v-233h-37l-6-4-4-6v-12l6-8 3-2 9-1h29v-240l2-7 4-5 5-3z"/><path fill="currentColor" transform="translate(784,351)" d="m0 0h95l9 2 7 8 1 2v10l-6 8-6 3h-106l-6-4-4-6v-12l4-6 5-4z"/><path fill="currentColor" transform="translate(784,287)" d="m0 0h94l10 2 7 8 1 2v10l-6 8-6 3h-106l-6-4-4-7v-11l6-8 3-2z"/><path fill="currentColor" transform="translate(109,367)" d="m0 0h51l8 2 5 5 3 5v10l-4 6-5 4-3 1h-58l-6-4-4-7v-11l4-6 5-4z"/><path fill="currentColor" transform="translate(750,687)" d="m0 0h34l9 3 5 5 2 4v10l-4 6-5 4-4 1h-41l-6-4-3-4-1-3v-10l3-6 6-5z"/><path fill="currentColor" transform="translate(913,160)" d="m0 0"/></svg>',
            "Location": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(474)" d="m0 0h78l4 2 28 5 26 7 25 9 18 8 23 12 22 14 21 16 10 9 8 7 11 10 7 8 10 11 13 17 12 17 16 28 10 21 9 24 7 24 5 22 4 29 1 12v34l-3 36-10 43-7 21-12 29-10 19-6 9-7 12-15 24-9 14-14 22-16 25-28 44-11 17-9 14 13 3 36 7 34 8 40 12 22 8 31 13 26 14 18 11 13 10 13 12 9 10 9 13 7 14 5 17 1 6v20l-3 16-8 19-10 15-9 10-2 3h-2l-2 4-11 9-15 11-22 13-26 13-33 13-48 14-27 7-58 11-37 5-58 6-20 2h-134v-1l-81-9-26-4-60-12-49-14-27-9-26-11-16-8-17-9-12-8-15-11-13-12-9-9-10-14-8-15-5-15-2-14 1-17 4-17 5-12 9-15 11-13 13-13 19-14 23-13 16-9 39-16 27-9 27-8 43-10 39-7h2l-12-20-11-17-70-110-19-29-13-24-10-23-9-27-9-38-3-27-2-25v-11l2-29 5-32 8-31 9-25 9-20 11-21 13-21 14-19 8-10 11-12 1-2h2l2-4 8-8 8-7 11-10 16-12 13-9 18-11 23-12 18-8 25-9 33-8 24-4zm36 60-31 2-24 4-23 6-22 8-25 12-22 13-17 13-11 9-16 15-11 12-8 10-11 15-14 23-11 23-8 21-8 29-4 25-1 11v36l3 29 7 30 7 21 11 26 8 14 8 13 12 19 11 17 12 19 28 44 16 25 21 33 16 25 56 88 11 17 12 19 14 22 13 20 2 3 3-1 13-21 13-20 14-22 11-17 12-19 15-23 11-18 13-20 35-55 32-50 35-55 11-17 21-35 7-14 11-28 7-26 4-22 2-25v-28l-3-27-4-20-7-24-8-21-10-21-15-25-14-18-9-10-11-12-14-13-17-13-15-10-21-12-22-10-30-10-23-5-25-3zm-139 673-46 7-42 9-27 7-37 12-30 13-21 11-15 10-14 12-9 10-6 12-1 4v10l4 10 7 9 6 7 13 10 27 16 10 5 39 16 52 15 33 7 39 7 41 5 31 3 39 2 27 1h42l52-2 35-3 51-6 38-7 33-7 45-13 15-5 42-18 28-17 11-9 10-10 6-10 2-7v-8l-4-12-9-12-8-8-13-10-26-15-24-11-21-8-39-12-48-11-42-7-15-2h-5l-12 19-14 22-16 25-14 22-18 28-14 22-10 16-12 18-8 8-6 3-7 2h-8l-10-3-10-9-8-11-11-18-15-23-12-19-14-22-16-25-35-55z"/><path fill="currentColor" transform="translate(509,181)" d="m0 0 26 2 14 3 17 5 16 8 11 6 12 9 14 12 9 10 11 15 9 16 6 15 6 21 3 28-3 30-7 24-10 21-8 13-13 15-6 7-14 11-8 6-18 10-12 5-20 6-22 3h-22l-21-3-22-7-19-9-11-7-10-8-10-9-9-9-11-14-9-16-6-12-8-26-3-26 1-17 3-21 8-25 13-24 4-6h2l2-4 9-11 9-9 9-7 11-8 18-10 27-9 22-3zm-9 62-17 4-12 5-11 7-11 9-9 10-9 16-5 13-3 14v22l3 14 5 13 7 13 11 13 11 9 16 9 15 5 12 2h17l16-3 13-5 10-5 12-9 6-5 10-13 8-15 5-18 1-8v-17l-3-16-5-13-7-13-11-13-9-8-17-10-15-5-11-2z"/></svg>',
            "Bluetooth": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(495,65)" d="m0 0 7 1 15 8 25 15 24 14 27 16 29 17 17 10 25 15 29 17 66 39 20 12 7 6 3 9-2 7-9 10-241 241 2 4 8 7 14 12 11 10 11 9 14 13 11 9 14 13 11 9 13 12 11 9 13 12 11 9 13 12 11 9 14 13 11 9 14 13 11 9 13 12 11 9 7 7 2 4v11l-6 7-14 11-18 14-26 20-18 14-13 10-17 13-36 28-17 13-14 11-26 20-18 14-13 10-18 14-17 13-11 8-5 2h-7l-6-3-5-5-1-5v-390l-193 193-8 4-9-2-7-6-2-5 1-9 6-8 205-205 5-4 1-2 1-14-6-7-11-9-15-14-11-9-12-11-8-7-10-9-11-9-13-12-11-9-13-12-8-7-14-12-11-10-8-7-14-12-10-9-8-7-10-9-11-9-13-12-11-9-10-10-2-4v-7l4-8 6-4 7-1 10 5 11 10 11 9 14 13 11 9 13 12 8 7 14 12 12 11 11 9 12 11 8 7 14 12 11 10 11 9 14 13 11 9 14 13 11 9 11 10h2v-375l3-7 6-5zm18 44v372l4-2 9-9 5-6 216-216v-2l-21-12-25-15-71-42-32-19-29-17-28-17-23-13zm0 416v388l7-4 16-13 12-9 13-10 14-11 13-10 18-14 13-10 18-14 13-10 36-28 17-13 10-8 13-10 17-13 5-4-2-4-11-9-13-12-8-7-15-13-10-9-8-7-14-12-11-10-8-7-15-13-10-9-8-7-14-12-10-9-8-7-10-9-11-9-12-11-8-7-14-12-10-9z"/></svg>',
            "permissions": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(444,32)" d="m0 0h7l33 11 333 120 33 12 9 5 4 6 1 4v250l-1 10-7 8-1 1h-13l-6-4-3-4-1-3v-233l-50 18-27 10-29 10-44 16-27 10-29 10-47 17-100 36-14 5-1 478 40-15 21-7 9 1 7 5 3 7-1 10-5 6-14 6-70 25h-12l-20-7-53-19-64-23-61-22-44-16-56-20-44-16-53-19-10-5-4-5-1-3v-521l6-8 14-6 55-20 45-16 55-20 192-69zm1 33-38 14-42 15-21 8-29 10-44 16-80 29-36 13-29 10-30 11 1 2 48 17 30 11 56 20 197 71 18 7 6-1 47-17 119-43 45-16 52-19 23-8 61-22v-2l-57-21-59-21-47-17-55-20-37-13-30-11-53-19-11-4zm-381 150v478l28 10 44 16 45 16 161 58 44 16 41 15 5 1v-477l-5-3-35-13-48-17-30-11-53-19-61-22-55-20-45-16-33-12z" fill="#0A0F28"/><path fill="currentColor" transform="translate(773,480)" d="m0 0h21l20 3 21 7 17 9 16 12 15 15 10 14 8 16 6 16 4 18 1 9v11l-3 7-6 6-10 1h-64l-7-3-4-5-2-5-2-12-5-10-4-5-12-6-4-1h-12l-10 4-7 6-5 9-2 7-1 69h196l14 3 10 6 10 9 6 10 3 9 1 10v216l-1 19-4 11-6 9-5 6-11 7-12 4-14 1h-316l-13-2-9-4-9-6-8-9-6-12-2-9v-237l2-9 8-14 8-8 10-6 8-3 6-1h38v-77l3-17 5-16 9-19 12-17 10-11 11-9 10-7 11-6 8-4 15-5 14-3zm0 32-15 3-14 5-13 7-10 8-12 12-7 10-8 16-4 13-2 12v74h31l1-1 1-71 4-16 8-14 9-10 10-7 13-6 11-2h13l13 2 12 5 9 6 9 8 7 11 7 15h32l1-3-7-20-8-15-11-13-7-7-13-9-14-7-13-4-12-2zm-155 192-7 6-3 6v232l3 6 6 5 4 1h325l7-3 5-5 2-8v-226l-3-8-6-5-2-1z" fill="#6569F4"/><path fill="currentColor" transform="translate(776,736)" d="m0 0h15l14 3 14 7 11 9 8 10 7 15 3 14v11l-2 12-4 10-5 9-8 9 1 9 17 51 1 10-3 6-6 6-8 1h-97l-6-2-5-4-3-6v-8l12-37 7-20-1-7-8-9-7-14-3-12v-18l4-15 7-13 11-12 10-7 10-5zm1 32-10 4-9 8-5 10-1 4v11l4 11 9 10 7 6 3 7-2 11-15 44v2h51l-1-6-14-43-1-10 5-8 9-7 6-8 3-11v-7l-3-10-6-9-9-6-8-3z" fill="#0A0F29"/></svg>',
            "extras": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(485,93)" d="m0 0h54l37 4 31 6 26 7 27 9 28 12 17 8 23 13 24 16 19 14 13 11 10 9 8 7 18 18 7 8 11 13 13 17 9 13 12 19 13 23 11 23 10 25 9 27 7 28 5 28 4 38v47l-4 37-5 27-8 32-11 32-13 30-9 17-6 11-12 20-10 14-14 19-10 11-9 11-23 23-8 7-14 12-19 14-18 12-18 11-18 10-31 14-24 9-31 9-33 7-29 4-27 2h-32l-27-2-28-4-29-6-28-8-25-9-21-9-23-11-27-16-22-15-10-8-14-11-26-24-15-16-10-11-13-17-9-12-10-15-13-22-12-23-11-25-10-28-7-25-6-28-4-27-2-21v-51l3-31 4-24 6-26 8-27 7-20 8-18 12-25 13-23 13-20 14-19 11-13 9-11 8-8 3-4h2l1-3 8-7 11-11 10-8 16-13 19-13 17-11 16-9 23-12 26-11 33-11 32-8 30-5zm1 65-27 3-31 6-31 9-28 11-23 11-27 16-14 10-13 10-11 9-12 11-9 8-7 8-8 8-11 14-10 13-12 18-9 15-11 21-10 23-12 36-6 25-4 25-2 24v40l2 23 5 30 6 24 10 30 10 23 8 16 8 15 18 27 14 18 10 11 7 8 18 18 22 18 18 13 25 15 23 12 23 10 31 10 25 6 24 4 20 2 18 1h25l24-2 32-5 24-6 33-11 29-13 19-10 19-12 14-10 13-10 21-18v-2l4-2 8-8v-2h2l7-8 13-15 9-12 14-21 12-21 8-16 10-23 10-30 7-30 4-26 2-24v-30l-2-27-4-26-5-23-7-24-7-19-12-27-13-24-11-17-11-15-8-10-11-13-5-6h-2l-2-4-12-12-11-9-13-11-15-11-20-13-24-13-26-12-28-10-27-7-12-3-28-4-14-1z"/><path fill="currentColor" transform="translate(503,307)" d="m0 0h17l12 6 8 9 4 10v147h138l11 1 12 6 8 9 4 10v14l-4 10-7 8-6 4-11 3h-144v29l-1 119-4 10-8 9-8 4-7 2h-12l-10-4-9-8-5-9-2-11v-141h-146l-11-4-9-8-6-12-1-11 4-13 9-10 12-6 7-1h141v-142l3-12 6-9 8-6z"/></svg>',
            "url": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="26" height="26" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(671,137)" d="m0 0h32l22 3 21 5 25 10 17 9 16 11 10 8 13 12 11 11 11 14 10 15 12 23 9 25 4 17 3 22v33l-4 25-5 19-8 21-11 21-8 12-8 10-7 9h-2l-2 4-152 152-14 11-10 7-5 2-2 4-6 9-8 11-15 16-144 144-11 9-11 8-11 7-12 7-24 10-20 6-23 4-10 1h-31l-22-3-26-7-13-5-21-10-14-9-11-8-10-9-8-7-13-14-14-19-10-18-8-17-7-21-5-24-2-20v-17l2-21 5-24 7-21 8-18 11-19 12-16 11-12 1-2h2l2-4 140-140 8-7 15-12 12-8 8-12 13-16 4-5h2l2-4 140-140 8-7 13-11 15-10 14-8 17-8 24-8 20-4zm3 29-24 3-25 7-22 10-16 10-13 10-16 15-139 139-9 11-9 12-9 16-8 18-5 15-4 18-2 18v20l2 18 5 21 7 19 8 16 9 14 10 13 15 16 12 10 15 10 17 9 16 6 16 5 5-2 6-6v-2h2l7-8 28-28v-2l-23-1-20-4-16-6-14-8-12-9-5-5h-2l-2-4-10-11-10-16-7-16-4-13-2-12v-28l4-19 6-16 7-14 8-11 18-20 135-135 11-9 14-9 12-6 15-5 19-3h22l19 3 17 6 17 9 16 12 13 13 11 16 9 19 4 13 3 18v22l-4 21-6 16-9 17-10 13-12 13-87 87 1 16v25l-2 19-3 15 4-2 135-135 9-11 10-14 11-21 8-22 5-25 1-11v-24l-3-21-7-25-9-20-8-14-10-14-12-13-11-11-16-12-15-9-19-9-19-6-21-4-11-1zm6 78-17 3-14 5-11 6-11 9-12 11-4 4v2l-4 2v2l-4 2v2l-4 2v2l-4 2v2l-4 2v2l-4 2v2l-4 2v2l-4 2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2l-7 8-7 6v2l-4 2-5 5v2l21 8 21 11 16 11 11 9 10 9 12 13 11 15 8 13 10 19 8 21 3-1v-2l4-2 8-8v-2l4-2v-2l4-2 64-64 10-14 7-15 4-15 1-6v-21l-3-16-6-15-9-15-11-12-15-11-17-8-16-4-8-1zm-163 132-46 46v1l26 2 18 4 16 6 14 8 12 9 10 9 11 14 9 15 7 18 4 19 1 19-2 19-4 15-6 15-9 16-9 11-11 12-137 137-14 11-13 8-11 5-11 4-13 3-9 1h-23l-17-3-16-5-16-8-11-7-11-9-8-8-10-13-9-16-6-16-4-19-1-16 2-19 4-16 5-14 9-16 10-13 4-4v-2h2v-2h2v-2h2v-2h2v-2h2v-2h2v-2l4-2v-2l4-2 38-38 7-6v-2l4-2 26-26-1-18v-21l3-25 2-12-7 6-10 10-6 5v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2h-2v2l-4 2-76 76v2h-2l-9 11-10 14-12 23-7 20-4 17-2 13v35l3 18 5 19 8 20 10 18 10 14 11 12 5 6 8 7 13 10 16 10 20 9 18 6 21 4 9 1h29l20-3 19-5 15-6 16-8 16-10 13-11 10-9 146-146 11-14 9-14 8-16 7-18 5-21 2-14v-34l-3-19-6-21-9-21-9-16-9-12-12-14-10-10-13-10-14-9-16-8-15-6-13-4zm-50 76-10 2-3 10v27l4 16 6 15 9 13 11 12 11 8 15 8 17 5 6 1h26l9-2 3-13v-20l-3-16-6-15-8-14-11-12-9-8-14-8-12-5-11-3-6-1zm-115 88-7 8-70 70v2h-2l-7 8-7 10-7 14-4 11-2 12v23l4 17 6 14 7 11 11 12 8 7 11 7 13 6 15 4 7 1h20l18-4 12-5 12-7 11-9 76-76 7-6-1-2-16-6-19-9-19-12-14-11-13-12-11-12-10-13-11-18-10-21-5-14z"/></svg>',
            "logging": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(66)" d="m0 0h533l3 2 19 7 16 9 11 9 10 10 10 14 8 16 5 16 2 13v227l-2 7-7 8-7 3h-12l-6-3-7-8-2-5-1-6-1-221-4-16-6-11-8-10-11-8-12-6-14-3h-346l3 2 36 12 40 13 41 14 19 7 13 7 11 9 8 8 9 14 6 13 3 11 1 8v691l151-1 14-2 13-5 12-8 7-7 7-10 5-14 2-9 1-224 4-10 8-7 6-2h8l8 3 5 5 4 6 1 3v227l-3 18-5 15-6 12-7 10-8 10-8 8-16 11-15 7-13 4-9 2-9 1h-157v51l-3 16-5 13-7 12-10 12-13 10-17 9-15 5h-31l-102-34-40-13-41-14-43-14-41-14-16-7-13-9-10-10-8-11-8-16-4-12v-803h2l1-7 6-15 9-14 13-13 10-7 14-7 10-3zm8 44-9 4-9 6-8 11-4 10-1 7v776l3 12 7 11 8 7 15 7 40 13 41 14 144 48 28 9 9 2h9l12-4 9-6 8-8 5-10 2-8v-782l-4-12-7-10-8-6-10-5-255-85-5-1z"/><path fill="currentColor" transform="translate(829,255)" d="m0 0 9 1 9 5 177 177v20l-177 177-10 5h-10l-9-4-5-6-3-7v-9l5-10 133-133-372-1-10-2-8-7-4-9v-8l3-8 5-5 6-4 3-1 377-1-7-8-127-127-3-5-1-4v-8l4-9 7-6z"/><path fill="currentColor" transform="translate(322,1023)" d="m0 0 2 1z"/></svg>',
            "intents": '<?xml version="1.0" encoding="UTF-8"?><svg version="1.1" class="me-2" viewBox="0 0 1024 1024" width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" transform="translate(666,25)" d="m0 0h15l12 3 14 7 12 11 9 14 12 21 14 24 12 21 10 17 4 7v2l15-5 5-1h21l8 2 12 5 9 6 10 9 7 10 6 14 2 9v18l-3 13-9 17-10 11-6 4 1 4 10 17 16 28 11 19 15 26 7 14 3 10v19l-3 11-7 14-10 11-11 7-13 5-14 2-14-2-13-5-11-8-9-10-3-5-3-1h-25l-29 2-31 4-36 7-38 10-25 8-21 7-32 13h-2l8 11 28 38 16 21 10 14 16 21 8 11 14 19 6 12 1 4v9l-4 12-7 9-8 7-14 13-14 7-4 1h-10l-11-4-10-9-16-21-13-18-16-21-14-19-16-21-13-18-10-13-6-8-7 1-12 6-17 5-13 2h-20l-20-4-16-6-14-8-10-8-14-14-10-15-7-15-4-13-2-11-1-12 2-21 5-18 5-12 10-16 12-13 10-9 21-13 23-13 24-14 18-10 6-1 8 1 14-11 16-13 14-12 11-10 8-7 13-13h2l2-4 18-18 9-11 8-9 1-2h2l2-4 13-17 10-14 11-17 10-17 1-1-1-7-5-13-1-5v-17l3-12 6-12 8-10 12-9 12-5zm2 29-8 3-8 6-6 10-1 5v10l5 13 14 24 30 52 14 24 13 23 10 17 15 26 8 14 14 24 13 23 10 17 12 21 14 24 12 20 9 8 8 3h13l12-6 7-8 3-8v-12l-4-11-13-23-16-27-14-25-16-27-14-25-16-27-14-25-16-27-14-25-16-27-14-25-16-27-7-7-8-4-4-1zm-28 90-11 18-13 19-11 14-13 16-6 7v2h-2l-7 8-11 12-29 29-8 7-12 11-10 8-14 12-11 8-9 7 2 6 10 17 16 28 11 19 30 52 1 2 6-1 27-11 34-12 29-9 32-8 35-7 27-4 22-2 28-1-1-5-14-25-14-24-16-28-14-24-16-28-14-24-30-52-14-24-6-10-1-3zm161 31-5 2 2 6 11 19 15 26 6 11 4-1 7-8 4-9 1-5v-12l-3-10-6-8-7-6-8-4-3-1zm-360 157-25 14-34 20-11 8-11 11-9 15-5 14-2 10v22l4 16 7 14 11 14 8 7 13 8 13 5 14 3h18l17-4 16-8 27-15 30-18-2-6-15-26-16-28-14-24-16-28-14-24zm96 160-24 14-8 5 6 9 14 18 10 14 10 13 14 19 16 21 28 38 6 8h5v-2l4-2 12-11 7-6 1-4-6-9-42-57-16-21-28-38-7-9z"/><path fill="currentColor" transform="translate(273,406)" d="m0 0 7 1 6 5 2 4v10l-6 7-16 5-27 7-24 8-24 10-25 12-17 10-19 13-14 11-13 12-13 13-11 14-10 15-6 11-8 20-5 18-2 12-1 19 2 22 5 20 8 20 8 15 9 13 10 13 15 16 11 10 17 13 15 10 19 11 23 12 7 6 1 3v9l-14 61-12 52-2 8 24-16 8-6 20-14 23-16 17-12 43-30 14-9h14l17 1h54l34-3 32-5 22-4v-41l4-11 9-10 8-5 12-2 111-1 13-12 15-15 9-12 10-15 9-17 7-19 5-22 1-7v-27l-4-22-7-21-8-16-8-14-11-14-9-11-14-14-11-9-10-9-3-5v-8l4-6 5-4 5-1 8 3 11 8 10 9 8 7 10 10 7 8 10 13 10 15 9 16 8 19 7 25 3 21v27l-3 21-7 25-8 19-9 16-8 12-12 16-10 11h72l12 3 9 6 6 8 3 6 1 5v175l-2 8-4 8-7 7-8 4-8 2-211 1-22-1-9-3-8-6-6-8-3-6-1-6v-100l5-5-25 5-26 4-29 3-15 1h-55l-20-1-23 16-17 12-23 16-16 11-80 56-14 9-6 3-10-3-5-6-1-9 12-53 16-69 7-28-6-2-25-14-19-13-13-10-14-12-22-22-11-14-7-10-8-13-8-16-7-17-6-23-2-13-1-12v-12l2-21 5-23 7-20 10-20 10-16 14-18 11-12 15-15 11-9 17-13 17-11 21-12 16-8 25-11 36-12 32-8zm248 397-1 1v173l100 1h112l18-1 1-1v-172l-3-1z"/<path fill="currentColor" transform="translate(162,17)" d="m0 0h34l10 3 6 4 6 10 3 16 4 5 5 3 9 1 8-3 10-7 11-2 10 3 8 6 20 20 5 8 1 3v11l-5 10-6 9v11l6 9 10 3 12 3 8 7 4 7 1 3v39l-4 9-5 6-9 4-15 3-3 3h-2l-2 5-1 3v10l6 10 4 7 1 3v11l-5 9-11 12-10 10-9 6-6 2h-9l-7-3-10-7-9-2-9 3-5 5-2 6-2 11-4 8-7 6-8 3h-39l-7-3-6-4-5-8-4-18-4-5-10-4-10 2-11 8-6 2h-8l-9-3-12-11-14-14-5-8-1-3v-13l3-6 7-10 1-10-3-7-5-5-4-2-13-2-8-5-6-7-3-9v-35l4-11 9-8 5-2 12-2 6-3 5-6 1-10-3-8-6-8-2-5v-13l4-8 2-3h2l2-4 4-4h2l2-4 9-9 8-5 7-2 10 1 10 6 6 4 9 1 8-3 5-5 2-7 2-11 5-8 8-6zm8 29-2 6-4 11-6 9-7 7-12 6-13 3h-8l-10-2-14-7-4 1-9 9v2h-2l1 5 4 7 3 8 1 6v10l-2 10-7 14-3 3v2l-4 2-9 6-8 3-9 3v19l9 3 11 5 9 7 7 10 5 12 1 6v11l-2 9-7 14 2 4 10 10 3 1 7-5 12-4 11-1 12 2 14 7 9 8 6 10 3 10 2 5h18l3-3 4-13 7-11 10-8 12-5 11-2 12 1 13 5 4 3 6-1v-2l4-2 2-4 4-2v-5l-5-8-3-10-1-11 3-14 5-10 5-6v-2h2v-2l16-8 11-3v-20l-6-2-13-5-9-7-8-11-5-13-1-12 3-14 4-8 2-2v-5l-12-12-5 1-12 6-9 2h-10l-12-3-10-5-9-8-8-14-3-12z"/><path fill="currentColor" transform="translate(933,455)" d="m0 0h10l13 4 13 8 11 9 9 10 6 10 6 13 4 16 1 6v30l-4 22-4 15-7 21-12 27-12 22-14 21-8 11-9 11-12 13-13 13-17 13-15 9-15 6-15 4-6 1h-16l-16-3-19-8-10-7-8-8-5-11-1-5v-8l4-13 16-28 9-14 9-8 10-4h17l12 5 11 6h5l6-5 15-20 13-21 8-15 8-19 4-12-1-6-12-7-9-7-6-8-4-9-1-5v-7l4-13 15-27 8-13 6-7 8-5zm2 29-7 10-14 25-3 9 4 5 15 9 8 8 5 11 1 5v9l-3 12-11 26-12 23-12 19-12 16-11 13-9 6-9 3h-13l-11-4-15-8-5 1-5 6-13 23-6 11 1 5 7 6 14 6 11 2h11l16-4 16-8 14-10 12-11 11-11v-2h2l11-14 13-18 14-24 13-28 9-27 4-19 1-7v-26l-3-13-7-14-9-10-8-6-10-5z"/><path fill="currentColor" transform="translate(174,94)" d="m0 0h13l17 3 12 5 11 6 9 7 11 11 9 14 6 15 3 14v21l-3 15-5 12-9 15-11 12-14 10-13 6-14 4-7 1h-21l-16-4-12-5-11-7-12-11-9-11-9-17-4-15-1-8v-15l3-16 5-13 7-12 8-10 7-7 13-9 15-7 12-3zm2 29-12 2-12 5-11 8-7 8-6 10-4 13-1 14 2 12 5 12 7 10 7 7 11 7 12 4 6 1h13l10-2 12-5 10-7 7-8 6-10 4-11 1-6v-14l-3-13-6-12-9-10-7-6-13-6-7-2z"/><path fill="currentColor" transform="translate(203,678)" d="m0 0h344l7 3 4 5 1 2v9l-4 6-6 4h-346l-6-3v-2h-2l-3-6 1-9 4-6z"/><path fill="currentColor" transform="translate(207,574)" d="m0 0h246l8 2 5 5 2 4v8l-6 8-4 2h-256l-5-3-4-5-1-9 3-6 5-5z"/><path fill="currentColor" transform="translate(591,830)" d="m0 0h8l16 8 17 10 28 16 22 13 6 5 2 5v7l-4 6-6 5-23 13-26 15-24 14-8 4h-7l-6-4-4-5-1-3v-98l5-8zm19 40v41l5-2 16-9 15-9v-2l-12-6-15-9-7-4z"/><path fill="currentColor" transform="translate(925,238)" d="m0 0h67l9 3 5 7v9l-4 6-6 4h-75l-8-7-1-2v-10l4-6 4-3z"/><path fill="currentColor" transform="translate(862,17)" d="m0 0 7 1 6 4 4 7-1 8-4 8-13 22-6 11-12 20-5 4-2 1h-9l-6-4-3-4-1-9 8-16 15-26 10-17 7-8z"/><path fill="currentColor" transform="translate(964,105)" d="m0 0h9l6 4 3 4 1 9-4 7-10 7-25 14-17 10-8 4-7 1-6-3-5-6-1-9 4-7 10-7 23-13 21-12z"/></svg>'
        
        }
        generate_html_table(output, icons,args.path)