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
    return output
    
                    

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
    '''
    <div class="accordion" id="accordionPanelsStayOpenExample">
  <div class="accordion-item">
    <h2 class="accordion-header" id="panelsStayOpen-headingOne">
      <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapseOne" aria-expanded="true" aria-controls="panelsStayOpen-collapseOne">
        Accordion Item #1
      </button>
    </h2>
    <div id="panelsStayOpen-collapseOne" class="accordion-collapse collapse show" aria-labelledby="panelsStayOpen-headingOne">
      <div class="accordion-body">
        <strong>This is the first item's accordion body.</strong> It is shown by default, until the collapse plugin adds the appropriate classes that we use to style each element. These classes control the overall appearance, as well as the showing and hiding via CSS transitions. You can modify any of this with custom CSS or overriding our default variables. It's also worth noting that just about any HTML can go within the <code>.accordion-body</code>, though the transition does limit overflow.
      </div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header" id="panelsStayOpen-headingTwo">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapseTwo" aria-expanded="false" aria-controls="panelsStayOpen-collapseTwo">
        Accordion Item #2
      </button>
    </h2>
    <div id="panelsStayOpen-collapseTwo" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-headingTwo">
      <div class="accordion-body">
        <strong>This is the second item's accordion body.</strong> It is hidden by default, until the collapse plugin adds the appropriate classes that we use to style each element. These classes control the overall appearance, as well as the showing and hiding via CSS transitions. You can modify any of this with custom CSS or overriding our default variables. It's also worth noting that just about any HTML can go within the <code>.accordion-body</code>, though the transition does limit overflow.
      </div>
    </div>
  </div>
  <div class="accordion-item">
    <h2 class="accordion-header" id="panelsStayOpen-headingThree">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapseThree" aria-expanded="false" aria-controls="panelsStayOpen-collapseThree">
        Accordion Item #3
      </button>
    </h2>
    <div id="panelsStayOpen-collapseThree" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-headingThree">
      <div class="accordion-body">
        <strong>This is the third item's accordion body.</strong> It is hidden by default, until the collapse plugin adds the appropriate classes that we use to style each element. These classes control the overall appearance, as well as the showing and hiding via CSS transitions. You can modify any of this with custom CSS or overriding our default variables. It's also worth noting that just about any HTML can go within the <code>.accordion-body</code>, though the transition does limit overflow.
      </div>
    </div>
  </div>
</div>
    '''
    count=0
    
    html = '<html><head><title>Flagged Results</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script></head><body>'
    #html += '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>'
    #html += '<table border="1">'
    #html += '<tr><th>C</th><th>Category</th><th>Details</th><th>Legitimate Use</th><th>Abuse</th></tr>'
    html += '<div>Categories</div>'
    html+= '<div class="accordion" id="accordionPanels">'
    for category, files in data.items():
        count+=1
        html += f'<div class="accordion-item"><h2 class="accordion-header" id="panelsStayOpen-heading{count}"><button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapse{count}" aria-expanded="true" aria-controls="panelsStayOpen-collapse{count}">{category}</button></h2>'
        html += f'<div id="panelsStayOpen-collapse{count}" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-heading{count}"><div class="accordion-body"><table class="table"><thead class="thead-dark"><tr><th scope="col">File Name</th><th scope="col">Details</th><th scope="col">Legitimate Use</th><th>Abuse</th></tr></thead><tbody>'
        for num, file in enumerate(files):
            if (category == "AndroidManifest"):
                html+=f'<tr><th scope="col">{file}</th><th scope="col">{data[category][num]["suspicious"]}</th><th scope="col">{data[category][num]["legitimate"]}</th><th scope="col">{data[category][num]["abuse"]}</th></tr>'
            else:
                for flagged in data[category][file]:
                    html+=f'<tr><th scope="col">{file}</th><th scope="col">{flagged["suspicious"]}</th><th scope="col">{flagged["legitimate"]}</th><th scope="col">{flagged["abuse"]}</th></tr>'
        html +='</tbody></table></div></div>'

    html +='</div>'
    '''
    for file, info in enumerate(files):
        html += f'<tr><td>{file_name}</td><td>{category_name}</td><td>{details}</td><td>{legitimate}</td><td>{abuse}</td></tr>'
        for item in items:
            details = item.get("suspicious", "")
            legitimate = item.get("legitimate", "")
            abuse = item.get("abuse", "")
            html += f'<tr><td>{file_name}</td><td>{category_name}</td><td>{details}</td><td>{legitimate}</td><td>{abuse}</td></tr>'
    '''
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

        generate_html_table(output) 

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