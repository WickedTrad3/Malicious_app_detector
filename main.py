#!/usr/bin/env python3
import os
from pathlib import Path
import rules
import json
import argparse
import sys
import subprocess
from prettytable import PrettyTable, MARKDOWN
import itertools



#malwh --help
#malwh -vv (everything)
#malwh -p (perm)
#malwh -u (url)
#malwh -A (api)
#malwh -i (intent)
#must decompile before any scanning
#malwh -d <filename> -o <output file> (decompile into file directory, otherwise write into temp)

#how to tell if obfuscated string or notimport itertools 

#all assuming in java
def check_folders(directory, cwd, permissions_check = False, url_check = False, apis_check = False, intent_check = False, logging_check = False, extra_check = False):
    first_iteration = True
    android_manifest_found = False
    for path, folders, files in os.walk(directory):
        
    # Open file
    # Open folder
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if (filename=="AndroidManifest.xml" or extension == "java"):
                    if (filename == "AndroidManifest.xml"):
                        android_manifest_found = True
                    
                    file_check = rules.File_read(filename, path)
                    file_check.check_strings(permissions_check, url_check, apis_check, intent_check, logging_check, extra_check)
                    if (file_check.is_flagged):
                        my_file = Path(cwd+"/flagged_files.json")
                        if (not my_file.is_file() or first_iteration):
                            json_create()
                            first_iteration = False
                            
                        #json create
                        json_update(file_check.__dict__)
                        
                    else:
                        pass
        
    if (not android_manifest_found):
        print("Android Manifest.xml not found")

def json_update(file_info):
    
    with open("flagged_files.json", "r") as outfile:
        #try:
        data = json.load(outfile)
        #except:
            #data = []
    file_name = file_info.pop("file_name")
    data[file_name] = file_info
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump(data, outfile, indent = 1)

def json_create():
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump({}, outfile)

def decompile(directory, cwd, method, outputpath):
    if (outputpath == None):
        outputpath = cwd
    if (sys.platform == "linux" or sys.platform == "linux2"):

        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.sh"), directory, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # Wait for process to complete.
        print("finished")

    elif platform == "win32":
        process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # Wait for process to complete.


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog = "malwh", description="APK Analysis CLI Tool")
    #parser.add_argument("-d", "--decompile", help="Decompile the APK to a specified output file.", default = False, required=False, action = "store_true")
    subparsers = parser.add_subparsers(help='help for subcommand', required = True, dest = "subcommand")
    parser.add_argument("path", help="full path of the apk", type=str)
    #decompilation
    parser_decompile = subparsers.add_parser('decompile', help='Decompile help')
    #parser_decompile.add_argument('-j',"--java", help='decompile into java souce code', default = False, required=False, action = "store_true")
    #parser_decompile.add_argument('-s',"--smali", help='decompile into smali bytecode', default = False, required=False, action = "store_true")
    parser_decompile.add_argument('decompile_method', help='decompilation method between java and smali', choices=('java', 'smali'))
    parser_decompile.add_argument('-o', '--output', help='output directory for decompiled source code', type=str)

    #analysis of the source code
    parser_analysis = subparsers.add_parser('analysis', help='Decompile help')
    parser_analysis.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-p", "--permissions", help="Decompile the APK to a specified output file.", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-u", "--urls", help="List all URLs found in the APK.", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-a", "--apis", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-i", "--intents", help="List all intents used in the APK.", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-l", "--logging", help="List all logging done in the APK.", default = False, required=False, action = "store_true")
    parser_analysis.add_argument("-e", "--extra", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")


    '''
    parser.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default = False, required=False, action = "store_true")
    parser.add_argument("-p", "--permissions", help="Decompile the APK to a specified output file.", default = False, required=False, action = "store_true")
    parser.add_argument("-u", "--urls", help="List all URLs found in the APK.", default = False, required=False, action = "store_true")
    parser.add_argument("-a", "--apis", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")
    parser.add_argument("-i", "--intents", help="List all intents used in the APK.", default = False, required=False, action = "store_true")
    parser.add_argument("-l", "--logging", help="List all logging done in the APK.", default = False, required=False, action = "store_true")
    parser.add_argument("-e", "--extra", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")
    '''
    args = parser.parse_args()
    cwd = os.path.dirname(__file__)
    non_verbose_mode = True
    if (not os.path.exists(args.path)):
        print("Error: Folder/File '"+args.path+"' not found. Please check the path and try again.")
    if (args.subcommand == "decompile"):
        if (os.path.isfile(args.path) and args.path.split(".")[-1]== "apk"):
            decompile(args.path, cwd, args.decompile_method, args.output)
        else:
            print("Error: File '"+args.path+"' not found. Please check the filename and try again.")
    else:
        if (args.very_verbose):
            check_folders(args.path,cwd,True,True,True,True,True,True)
            non_verbose_mode = False
        elif (non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging or args.extra)):
            check_folders(args.path, cwd, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extra)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")
    '''
    if (args.very_verbose):
        check_folders(args.path,cwd,True,True,True,True,True,True)
        non_verbose_mode = False
    elif (non_verbose_mode):
        check_folders(args.path, cwd, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extra)
    '''
    #add pretty tables
    #adding permissions to android manifest
    table = PrettyTable()
    table.padding_width = 4
    table.set_style(MARKDOWN)
    with open("flagged_files.json", "r") as outfile:
        data = json.load(outfile)
    data["AndroidManifest.xml"]
    table.add_column("Permissions",data["AndroidManifest.xml"]["flagged"]["permissions"])

    perms_table = table.get_string()
    table.clear()

    #adding intents to android manfiest
    table.add_column("Email",data["AndroidManifest.xml"]["flagged"]["intent"]["email"])
    table.add_column("Others",data["AndroidManifest.xml"]["flagged"]["intent"]["others"])

    table_data = perms_table + "\n\n" + table.get_string()
    with open('Android_manifest_examined.txt', 'w') as f:
        f.write(table_data)
    table.clear()

    #API used
    data.pop("AndroidManifest.xml")
    file_names = data.keys()
    for file_name in file_names:
        table.field_names = ["File_name", "requestWindowFeature","PackageManager","Calendar", "System", "sms", "click","accessibility", "Android"]
        requestWindowFeature = data[file_name]["flagged"]["API"]["requestWindowFeature"]
        PackageManager = data[file_name]["flagged"]["API"]["PackageManager"]
        Calendar = data[file_name]["flagged"]["API"]["Calendar"]
        System = data[file_name]["flagged"]["API"]["System"]
        sms = data[file_name]["flagged"]["API"]["sms"]
        click = data[file_name]["flagged"]["API"]["click"]
        accessibility = data[file_name]["flagged"]["API"]["accessibility"]
        Android = data[file_name]["flagged"]["API"]["Android"]
        for (requestWindowFeature_line, PackageManager_line, Calendar_line, System_line, sms_line, click_line, accessibility_line, Android_line) in itertools.zip_longest(requestWindowFeature, PackageManager, Calendar, System, sms, click, accessibility, Android):
            table.add_row([file_name, requestWindowFeature_line, PackageManager_line, Calendar_line, System_line, sms_line, click_line, accessibility_line, Android_line])

    table_data = table.get_string()
    with open('API_examined.txt', 'w') as f:
        f.write(table_data)
    table.clear()

    #other flagged items
    for file_name in file_names:
        table.field_names = ["File_name", "url", "extra"]
        url = data[file_name]["flagged"]["url"]
        extra = data[file_name]["flagged"]["extra"]

    table_data = table.get_string()
    with open('others.txt', 'w') as f:
        f.write(table_data)
    table.clear()
    #late
    #add generation of report