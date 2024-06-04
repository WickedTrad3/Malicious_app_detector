import os
from pathlib import Path
import rules
#all assuming in java
def check_folders(directory):
    
    for path, folders, files in os.walk(directory):
    # Open file
        for filename in files:
            with open(os.path.join(path, filename)) as f:
                print(directory)
                extension = filename.split(".")[1]
                if (extension=="xml" or extension == "java"):
                    file_check = rules.File_read(filename, path)
                    file_check.check_rule_set()
                    file_check.Check_strings()
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
'''
def main():
    directory = input("enter directory of decompiled apk: ")
    check_folders(directory)
main()