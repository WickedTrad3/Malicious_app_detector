import os
from pathlib import Path
import rules
import json
import argparse

#!/usr/bin/env python

#malwh --help
#malwh -vv (everything)
#malwh -p (perm)
#malwh -u (url)
#malwh -A (api)
#malwh -i (intent)
#must decompile before any scanning
#malwh -d <filename> -o <output file> (decompile into file directory, otherwise write into temp)

#all assuming in java
def check_folders(directory):
    
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
                    file_check.check_strings()
                    if (file_check.suspicious):
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
        data = json.load(outfile)
    data.append(file_info)
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump(data, outfile, indent = 1)

def json_create():
    with open("flagged_files.json", "w+") as outfile:
        data = json.dump([], outfile)

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
main()