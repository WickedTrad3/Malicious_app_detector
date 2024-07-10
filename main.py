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

# def get_current_time():
#     return time.strftime("%H-%M-%S-%d-%m-%Y")

# def get_identifier_from_path(path):
#     parts = path.split(os.sep)
#     parts = [part for part in parts if part]
#     return parts[-2] if len(parts) > 1 else parts[-1]

# def get_unique_directory_name(base_name, parent_directory="."):
#     current_time = time.strftime("%H-%M-%S-%d-%m-%Y")
#     return current_time

def check_folders(directory, cwd, options):
    first_iteration = True
    android_manifest_found = False
    path_to_json = './rules/'
    json_files = [("./rules/" + pos_json) for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
    output = {}
    
    # identifier = get_identifier_from_path(directory)
    # new_directory_name = get_unique_directory_name(identifier, cwd)
    new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")
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
    json_update(output, new_directory_path)
    return output

def create_output(ruleset, ruleset_name, output):
    output[ruleset_name] = {}
    for pattern in ruleset:
        if (ruleset_name =="code_apis"):
            output[ruleset_name][pattern["category"]] = {}
    return output

def json_update(output, new_directory_path):
    current_time = time.strftime("%H-%M-%S-%d-%m-%Y")
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:
        json.dump(output, outfile, indent=1)

def json_create(new_directory_path):
    current_time = time.strftime("%H-%M-%S-%d-%m-%Y")
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:
        json.dump({}, outfile)

def decompile(apk_path, cwd, method, outputpath):
    if outputpath is None:
        outputpath = cwd
    if sys.platform == "linux" or sys.platform == "linux2":
        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.sh"), apk_path, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.

    elif sys.platform == "win32":
        process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.
    try:
        with open(apk_path, "rb") as file:
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
            "file_size": os.stat(apk_path).st_size/1000000,
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
        print(f"Decompilation of {apk_path} complete. File metadata is stored inside flagged_items")
    except:
        print(f'Error: Output folder "{outputpath}" cannot be written into. Please check the folder and try again.')

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
    html_report += '<style>.accordion {--bs-accordion-btn-color: #fdfffc;--bs-accordion-btn-bg:  #2a2a2a;--bs-accordion-active-color: #8ccd00;--bs-accordion-active-bg: #2a2a2a;} .accordion-button:after {background: #2a2a2a;} .accordion-button:not(.collapsed)::after {background: #2a2a2a; color:#fdfffc;}</style>'
    html_report += '<body style="background-color:#010811;color: #fdfffc;">'
    html_report += '\n<div class="container-fluid border border border-white rounded mt-2">'

    html_report += '<div class="row"><div class="col"><p>Malwhere</p></div><div class="col">'
    html_report += f'<div class="row"><div class="col"><p>Package name:</p></div><div class="col"><p>{content["package name"]}</p></div></div>'
    
    html_report += '<div class="row">'
    html_report += f'<div class="col"><p>File size:</p></div><div class="col"><p>{content["file_size"]}MB</p></div></div>'
    
    html_report += '<div class="row">'
    html_report += f'<div class="col"><p>MD5:</p></div><div class="col"><p>{content["MD5"]}</p></div></div></div></div></div>'

    html_report += '\n<h1 class="text-center">Categories</h1>\n'
    html_report += '\n<div class="accordion container-fluid" id="accordionPanel">\n'
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
                html_report += '\t\t\t\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col border border-white">File Name and Line Number</div><div class="col-6 border border-white">Details</div><div class="col border border-white">Legitimate Use</div><div class="col border border-white">Abuse</div></div>\n'
                for file_path, list_details in files.items():
                    file_name = file_path.split("/")[-1]
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t\t\t\t<div class="row"><div class="col border border-white" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="right">{file_name}: Line {detail["line number"]}</div><div class="col-6 border border-white">{html.escape(detail["suspicious"])}</div ><div class="col border border-white">{detail["legitimate"]}</div><div class="col border border-whites">{detail["abuse"]}</div></div>\n'
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
                html_report += '\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col border border-white">Line Number</div><div class="col-6 border border-white">Details</div><div class="col border border-white">Legitimate Use</div><div class="col border border-white">Abuse</div></div>\n'
                for file_path, list_details in files.items():
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t<div class="row"><div class="col border border-white">{detail["line number"]}</div><div class="col-6 border border-white"">{html.escape(detail["suspicious"])}</div><div class="col border border-white"">{detail["legitimate"]}</div><div class="col border border-white"">{detail["abuse"]}</div></div>'
            else:
                html_report += '\t\t\t\t\t\t<div class="container-fluid text-center text-white"><div class="row"><div class="col border border border-white">File Name and Line Number</div><div class="col-6 border border-white">Details</div><div class="col border border-white">Legitimate Use</div><div class="col border border-white">Abuse</div></div>\n'
                
                for file_path, list_details in files.items():
                    file_name = file_path.split("/")[-1]
                    for detail in list_details:
                        html_report += f'\t\t\t\t\t\t<div class="row"><div class="col border border border-white" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="right">{file_name}: Line {detail["line number"]}</div><div class="col-6 border border border-white">{html.escape(detail["suspicious"])}</div><div class="col border border border-white">{detail["legitimate"]}</div><div class="col border border border-white">{detail["abuse"]}</div></div>\n'
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
        with open(output_filename, 'w+') as flagged:
            flagged.write(html_report)
        print(f"Saved output as {output_filename}")
    except:
        print("error creating flagged_results.html. please check if path is a decompiled apk and try again.")

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def get_categories(file_path):
    data = load_json(file_path)
    categories = set(entry['category'] for entry in data)
    return sorted(categories)

def add_new_rule(file_path):
    data = load_json(file_path)
    suspicious = input("Enter the suspicious item: ").strip()
    
    if any(entry['suspicious'].lower() == suspicious.lower() for entry in data):
        print(f"The suspicious item '{suspicious}' already exists. Exiting...")
        return
    
    legitimate = input("Enter the legitimate reasoning: ").strip()
    abuse = input("Enter the potential abuse: ").strip()
    
    if os.path.basename(file_path) == "code_apis.json":
        categories = get_categories(file_path)
        print("Choose the category for the new rule:")
        for idx, category in enumerate(categories, start=1):
            print(f"{idx}. {category}")
        
        category_choice = input("Enter the number to select the category: ").strip()
        try:
            category_idx = int(category_choice) - 1
            if 0 <= category_idx < len(categories):
                category = categories[category_idx]
            else:
                print("Invalid category choice. Exiting...")
                return
        except ValueError:
            print("Invalid input. Exiting...")
            return

        new_rule = {
            "suspicious": suspicious,
            "legitimate": legitimate,
            "category": category,
            "abuse": abuse
        }
    else:
        new_rule = {
            "suspicious": suspicious,
            "legitimate": legitimate,
            "abuse": abuse
        }

    data.append(new_rule)
    save_json(file_path, data)
    print(f"New rule added to {file_path}.")

def remove_rule(file_path):
    data = load_json(file_path)
    suspicious = input("Enter the suspicious item to remove: ").strip()
    
    item_index = next((i for i, entry in enumerate(data) if entry['suspicious'].lower() == suspicious.lower()), None)
    
    if item_index is not None:
        removed_item = data.pop(item_index)
        save_json(file_path, data)
        print(f"Removed rule: {removed_item}")
    else:
        print(f"The suspicious item '{suspicious}' was not found.")

def modify_rule(file_path):
    data = load_json(file_path)
    suspicious = input("Enter the suspicious item to modify: ").strip()
    
    item_index = next((i for i, entry in enumerate(data) if entry['suspicious'].lower() == suspicious.lower()), None)
    
    if item_index is not None:
        print(f"Current rule: {data[item_index]}")
        new_suspicious = input("Enter the new suspicious item name (leave blank to keep current): ").strip()
        legitimate = input("Enter the new legitimate reasoning (leave blank to keep current): ").strip()
        abuse = input("Enter the new potential abuse (leave blank to keep current): ").strip()
        
        if os.path.basename(file_path) == "code_apis.json":
            categories = get_categories(file_path)
            print("Choose a new category (leave blank to keep current):")
            for idx, category in enumerate(categories, start=1):
                print(f"{idx}. {category}")
            category_choice = input("Enter the number of the category: ").strip()
            if category_choice:
                try:
                    category_idx = int(category_choice) - 1
                    if 0 <= category_idx < len(categories):
                        data[item_index]['category'] = categories[category_idx]
                    else:
                        print("Invalid category choice. Keeping current category.")
                except ValueError:
                    print("Invalid input. Keeping current category.")
        
        if new_suspicious:
            if new_suspicious.lower() != data[item_index]['suspicious'].lower() and any(
                entry['suspicious'].lower() == new_suspicious.lower() for entry in data):
                print(f"The new suspicious item '{new_suspicious}' already exists. Cannot modify to this name.")
                return
            data[item_index]['suspicious'] = new_suspicious
        if legitimate:
            data[item_index]['legitimate'] = legitimate
        if abuse:
            data[item_index]['abuse'] = abuse
        
        save_json(file_path, data)
        print(f"Modified rule: {data[item_index]}")
    else:
        print(f"The suspicious item '{suspicious}' was not found.")

def update_rules():
    rules_folder = "rules"
    if not os.path.exists(rules_folder):
        print(f"The folder '{rules_folder}' does not exist.")
        return

    json_files = [f for f in os.listdir(rules_folder) if f.endswith('.json')]

    if not json_files:
        print("No JSON files found in the 'rules' folder.")
        return

    print("Choose a file to add, remove, or modify a rule:")
    for idx, file_name in enumerate(json_files, start=1):
        print(f"{idx}. {os.path.splitext(file_name)[0]}")
    
    choice = input("Enter the number of the file: ").strip()
    
    try:
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(json_files):
            file_path = os.path.join(rules_folder, json_files[choice_idx])
            action = input("Do you want to (a)dd, (r)emove, or (m)odify a rule? ").strip().lower()
            if action == 'a':
                add_new_rule(file_path)
            elif action == 'r':
                remove_rule(file_path)
            elif action == 'm':
                modify_rule(file_path)
            else:
                print("Invalid action. Exiting...")
        else:
            print("Invalid choice. Exiting...")
    except ValueError:
        print("Invalid input. Exiting...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="malwh", description="APK Analysis CLI Tool")
    
    subparsers = parser.add_subparsers(help='help for subcommand', required=True, dest="subcommand")
    # parser.add_argument("path", help="full path of the apk", type=str)

    parser_decompile = subparsers.add_parser('decompile', help='Decompile help')
    parser_decompile.add_argument('decompile_method', help='decompilation method between java and smali', choices=('java', 'smali'))
    parser_decompile.add_argument('-o', '--output', help='output directory for decompiled source code', type=str)
    parser_decompile.add_argument("path", help="full path of the apk", type=str)

    parser_analysis = subparsers.add_parser('analysis', help='Analysis help')
    parser_analysis.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-p", "--permissions", help="Scan for permissions", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-u", "--urls", help="List all URLs found in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-a", "--apis", help="List all APIs used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-i", "--intents", help="List all intents used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-l", "--logging", help="List all logging done in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-e", "--extras", help="List all extras used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("path", help="full path of the apk", type=str)

    parser_modify_rules = subparsers.add_parser('modify-rules', help='Modify JSON rules')
    
    args = parser.parse_args()
    cwd = os.path.dirname(__file__)
    non_verbose_mode = True
    # if not os.path.exists(args.path):
    #     print("Error: Folder/File '"+args.path+"' not found. Please check the path and try again.")
    #     sys.exit(1)
    if args.subcommand in ["decompile", "analysis"] and not os.path.exists(args.path):
        print("Error: Folder/File '"+args.path+"' not found. Please check the path and try again.")
        sys.exit(1)

    # identifier = get_identifier_from_path(args.path)
    new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")

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
    elif args.subcommand == "analysis":
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


        try:
            with open("./icons/icons.json") as icons_json:
                icons = json.load(icons_json)
            generate_html_table(output, icons,args.path)
        except:
            print("error loading icons.json. Please check the file and ensure it is correct")

    elif args.subcommand == "modify-rules":
        update_rules()