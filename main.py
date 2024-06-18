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
    for path, folders, files in os.walk(directory):
        
    # Open file
    # Open folder
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if (filename=="AndroidManifest.xml" or extension == "java"):

                    
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
                        #print("Not suspicious: " + file_check.file_name)

                    #print(e)
                    #print(path)
                    #print(file_check.file_name)
                    #json_update({file_check.file_name:"doesnt work"})

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

def decompile(directory, cwd):
    if (sys.platform == "linux" or sys.platform == "linux2"):

        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.sh"), directory, cwd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # Wait for process to complete.
        print("finished")

    elif platform == "win32":
        process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # Wait for process to complete.
'''
{
 "path of file": {
            "name":self.file_name,
            "suspicious_permissions": [],
            "API": [],
            "intent": [],
            "url": []
        }

}

def create_parser():
    parser = argparse.ArgumentParser(description="Command-line Todo List App")
    parser.add_argument("-a", "--add", metavar="", help="Add a new task")
    parser.add_argument("-l", "--list", action="store_true", help="List all tasks")
    parser.add_argument("-r", "--remove", metavar="", help="Remove a task by index")
    return parser
'''
def main():
    #parser = create_parser()
    #args = parser.parse_args()
    directory = input("enter directory of decompiled apk: ")
    json_create()
    check_folders(directory)

parser = argparse.ArgumentParser(prog = "malwh", description="Command-line Todo List App")
parser.add_argument("-d", "--decompile", help="Decompile the APK to a specified output file.", default = False, required=False, action = "store_true")
parser.add_argument("path", help="full path of the apk", type=str)
parser.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default = False, required=False, action = "store_true")
parser.add_argument("-p", "--permissions", help="Decompile the APK to a specified output file.", default = False, required=False, action = "store_true")
parser.add_argument("-u", "--urls", help="List all URLs found in the APK.", default = False, required=False, action = "store_true")
parser.add_argument("-a", "--apis", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")
parser.add_argument("-i", "--intents", help="List all intents used in the APK.", default = False, required=False, action = "store_true")
parser.add_argument("-l", "--logging", help="List all logging done in the APK.", default = False, required=False, action = "store_true")
parser.add_argument("-e", "--extra", help="List all APIs used in the APK.", default = False, required=False, action = "store_true")
#mutually exclusive group to seperate decompile and other perms
args = parser.parse_args()
cwd = os.path.dirname(__file__)
non_verbose_mode = True
if (len(sys.argv) <2):
    print("Error: No options specified. Use 'malwh --help' to see available commands and options.")
elif (args.decompile):
    decompile(args.path, cwd)
if (args.very_verbose):
    check_folders(args.path,cwd,True,True,True,True,True,True)
    non_verbose_mode = False
elif (non_verbose_mode):
    check_folders(args.path, cwd, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extra)

#add pretty tables
table = PrettyTable()
table.padding_width = 4
table.set_style(MARKDOWN)
with open("flagged_files.json", "r") as outfile:
    data = json.load(outfile)
data["AndroidManifest.xml"]
#table.field_names = ["Permissions"]
table.add_column("Permissions",data["AndroidManifest.xml"]["flagged"]["permissions"])
print("Android Manifest permissions and intents found")

perms_table = table.get_string()
table.clear()

#data["AndroidManifest.xml"]["flagged"]["intent"]
table.add_column("Email",data["AndroidManifest.xml"]["flagged"]["intent"]["email"])
table.add_column("Others",data["AndroidManifest.xml"]["flagged"]["intent"]["others"])

table_data = perms_table + "\n\n" + table.get_string()
with open('Android_manifest_examined.txt', 'w') as f:
    f.write(table_data)
table.clear()

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