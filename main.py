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

def check_folders(directory, cwd, options):
    first_iteration = True
    android_manifest_found = False

    output = {
            "AndroidManifest": [],
            "SMS and Communication":{},
            "Device Information and System Interaction":{},
            "Network Communication": {},
            "Contacts and Communication": {},
            "File and Data Handling": {},
            "Cryptography and Data Storage": {},
            "Media and Camera": {},
            "System and Reflection":{},
            "User Interface and Accessibility":{},
            "Location and Communication": {},
            "Content Providers and Databases": {},
            "Audio and Video": {},
            "Bluetooth and Communication": {},
            "File Access and Storage": {},
            "Camera and Media": {},
            "Accessibility and System Settings": {},
            "Potential obfuscation": {},
            "Ransomware": {},
            "Logging":{},
            "General intent usage.": {},
            "Intent mail function.": {},
            "Intent communication.": {},
            "Data related intent.": {}
        }

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
                    

    if not android_manifest_found:
        print("Android Manifest.xml not found")


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

def generate_html_table(data):
    html = '<html><head><title>Flagged Results</title></head><body>'
    html += '<table border="1">'
    html += '<tr><th>File Name</th><th>Category</th><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>'

    for file_name, categories in data.items():
        for category_index, items in enumerate(categories):
            category_name = ['Permissions', 'URLs', 'Code and APIs', 'Logging', 'Intents', 'Extras'][category_index]
            for item in items:
                details = item.get("suspicious", "")
                legitimate = item.get("legitimate", "")
                abuse = item.get("abuse", "")
                html += f'<tr><td>{file_name}</td><td>{category_name}</td><td>{details}</td><td>{legitimate}</td><td>{abuse}</td></tr>'

    html += '</table>'
    html += '</body></html>'
    html += '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>'
    

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
            check_folders(args.path, cwd, options)
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
            check_folders(args.path, cwd, options)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
        
    
        with open("flagged_files.json", "r") as outfile:
            data = json.load(outfile)

        generate_html_table(data) 

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