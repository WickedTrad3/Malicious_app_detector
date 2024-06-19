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

# malwh --help
# malwh -vv (everything)
# malwh -p (perm)
# malwh -u (url)
# malwh -A (api)
# malwh -i (intent)
# must decompile before any scanning
# malwh -d <filename> -o <output file> (decompile into file directory, otherwise write into temp)

# how to tell if obfuscated string or notimport itertools 

# all assuming in java
def check_folders(directory, cwd, permissions_check = False, url_check = False, apis_check = False, intent_check = False, logging_check = False, extra_check = False):
    first_iteration = True
    android_manifest_found = False
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java":
                if filename == "AndroidManifest.xml":
                    android_manifest_found = True

                file_path = os.path.join(path, filename)
                results = rules.scan_file(file_path, permissions_check, url_check, apis_check, intent_check, logging_check, extra_check)

                if any(results):
                    my_file = Path(cwd + "/flagged_files.json")
                    if not my_file.is_file() or first_iteration:
                        json_create()
                        first_iteration = False

                    json_update({filename: results})

                else:
                    pass

    if not android_manifest_found:
        print("Android Manifest.xml not found")

def check_folders(directory, cwd, permissions_check = False, url_check = False, apis_check = False, intent_check = False, logging_check = False, extra_check = False):
    first_iteration = True
    android_manifest_found = False
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[-1]
            except:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java" or extension == "smali":
                if filename == "AndroidManifest.xml":
                    android_manifest_found = True
                
                file_path = os.path.join(path, filename)
                results = rules.scan_file(file_path, permissions_check, url_check, apis_check, intent_check, logging_check, extra_check)
                if any(results):
                    
                    my_file = Path(cwd + "/flagged_files.json")
                
                    if not my_file.is_file() or first_iteration:
                        json_create()
                        first_iteration = False
                    json_update({file_path:results})

    if not android_manifest_found:
        print("Android Manifest.xml not found")


def json_update(file_info):
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)
    file_name = list(file_info.keys())[0]
    data[file_name] = file_info[file_name]
    with open("flagged_files.json", "w+") as outfile:
        json.dump(data, outfile, indent=1)

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
            check_folders(args.path, cwd, True, True, True, True, True, True)
            non_verbose_mode = False
        elif non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging or args.extras):
            check_folders(args.path, cwd, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extras)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
    
      # add pretty tables
    table = PrettyTable()
    table.padding_width = 4
    table.set_style(MARKDOWN)
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)

    # adding permissions to android manifest
    for key in data.keys():
        if ("AndroidManifest.xml" in key):
            
            print("android")
            table.add_column("Permissions", data[key][0])
            perms_table = table.get_string()
            table.clear()

            # adding intents to android manifest
            table.add_column("Email", data[key][4])

            table_data = perms_table + "\n\n" + table.get_string()
            with open('Android_manifest_examined.txt', 'w') as f:
                f.write(table_data)
            table.clear()
            data.pop(key)
            break

    # API used
    file_names = data.keys()
    for file_name in file_names:
        table.field_names = ["File_name", "API"]
        API_info = data[file_name][2]
        table.add_row([file_name, API_info])
    
    table_data = table.get_string()
    with open('API_examined.txt', 'w') as f:
        f.write(table_data)
    table.clear()

    # other flagged items
    for file_name in file_names:
        table.field_names = ["File_name", "url","logging", "extra"]
        url = data[file_name][1]
        logging = data[file_name][3]
        extra = data[file_name][5]
        for (url_line, logging_line, extra_line) in itertools.zip_longest(url, logging, extra):
            table.add_row([file_name, url_line, logging_line, extra_line])
    table_data = table.get_string()
    with open('others.txt', 'w') as f:
        f.write(table_data)
    table.clear()