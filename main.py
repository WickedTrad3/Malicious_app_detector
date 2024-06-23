#!/usr/bin/env python3
import os
from pathlib import Path
import rules
import json
import argparse
import sys
import subprocess

def check_folders(directory, cwd, permissions_check=False, url_check=False, apis_check=False, intent_check=False, logging_check=False, extra_check=False):
    first_iteration = True
    android_manifest_found = False
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except IndexError:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java" or extension == "smali":
                if filename == "AndroidManifest.xml":
                    android_manifest_found = True

                file_path = os.path.join(path, filename)
                results = rules.scan_file(file_path, permissions_check, url_check, apis_check, logging_check, intent_check, extra_check)
                if any(results):
                    my_file = Path(cwd + "/flagged_files.json")
                    if not my_file.is_file() or first_iteration:
                        json_create()
                        first_iteration = False
                    json_update({file_path: results})

    if not android_manifest_found:
        print("AndroidManifest.xml not found")

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
        print("Error: Folder/File '" + args.path + "' not found. Please check the path and try again.")
        sys.exit(1)

    if args.subcommand == "decompile":
        if os.path.isfile(args.path) and args.path.split(".")[-1] == "apk":
            decompile(args.path, cwd, args.decompile_method, args.output)
        else:
            print("Error: File '" + args.path + "' not found. Please check the filename and try again.")
    else:
        if args.very_verbose:
            check_folders(args.path, cwd, True, True, True, True, True, True)
            non_verbose_mode = False
        elif non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging or args.extras):
            check_folders(args.path, cwd, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extras)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
    
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)

    generate_html_table(data)
