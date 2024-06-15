import os
from pathlib import Path
import rules
import json
import argparse
from sys import platform
import subprocess

#!/usr/bin/env python

#malwh --help
#malwh -vv (everything)
#malwh -p (perm)
#malwh -u (url)
#malwh -A (api)
#malwh -i (intent)
#must decompile before any scanning
#malwh -d <filename> -o <output file> (decompile into file directory, otherwise write into temp)

#how to tell if obfuscated string or not

#all assuming in java
def check_folders(directory, permissions_check = False, url_check = False, apis_check = False, intent_check = False, logging_check = False, extra_check = False):
    
    for path, folders, files in os.walk(directory):
        print("current path: " + path)
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
        try:
            data = json.load(outfile)
        except:
            data = []
    data.append(file_info)
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump(data, outfile, indent = 1)

def json_create():
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump([], outfile)

def decompile(directory, cwd):
    if (platform == "linux" or platform == "linux2"):

        process = subprocess.Popen([os.path.normpath(cwd + "decompile.sh"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait() # Wait for process to complete.

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

if (args.decompile):
    decompile(args.path, cwd)
if (args.very_verbose):
    check_folders(args.path,True,True,True,True,True,True)
    non_verbose_mode = False
elif (non_verbose_mode):
    print("non verbose mode")
    check_folders(args.path, args.permissions, args.urls, args.apis, args.intents, args.logging, args.extra)

#add pretty tables
#later
#add generation of report