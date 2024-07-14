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
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

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

    for rule_path in json_files:
        try:
            with open(rule_path, "r") as outfile:
                ruleset = json.load(outfile)
            if options[rule_path]:
                create_output(ruleset, rule_path.split("/")[-1].split(".")[0], output)
        except json.decoder.JSONDecodeError:
            print(f"Error occurred with {rule_path}")

    file_paths = []
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java" or extension == "smali":
                if filename == "AndroidManifest.xml":
                    android_manifest_found = True
                file_paths.append(os.path.join(path, filename))

    with ThreadPoolExecutor(max_workers=8) as executor:  # Adjust the number of workers as needed
        futures = {executor.submit(analyse_file, file_path, cwd, options, output): file_path for file_path in file_paths}
        for future in as_completed(futures):
            file_path = futures[future]
            try:
                result = future.result()
                output.update(result)
            except Exception as e:
                print(f"Error analysing {file_path}: {e}")

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
        process = subprocess.Popen([os.path.normpath(cwd + "/decompile.bat"), apk_path, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()  # Wait for process to complete.
    try:
        with open(apk_path, "rb") as file:
            content = file.read()
            content = content.decode('utf-8', errors='ignore')
            digest = hashlib.file_digest(file, "md5")
        if (method == "java"):
            with open(outputpath+"/jadx_decompiled/resources/AndroidManifest.xml", "r", encoding="utf-8") as file:
                content = file.read()
            outputpath = outputpath+"/jadx_decompiled/"
        elif (method == "smali"):
            with open(outputpath+"/apktool_decompiled/AndroidManifest.xml", "r", encoding="utf-8") as file:
                content = file.read()
            outputpath = os.path.abspath(outputpath,"/apktool_decompiled/")
        package_name = re.findall(r'(package=\")(.*?)(\")', content)[0][1]
        stat = {
            "File Size": os.stat(apk_path).st_size/1000000,
            "MD5": digest.hexdigest(),
            "Package Name": package_name
        }
        outputpath = os.path.abspath(outputpath)
        if (method == "java"):
        #change to include apktool_decompiled/jadx_decompiled folder
            with open(outputpath+"/file_stat.json", 'w') as outfile:
                json.dump(stat, outfile, indent=1)
        else:
            with open(outputpath+"/file_stat.json", 'w') as outfile:
                json.dump(stat, outfile, indent=1)
        print(f"Decompilation of {apk_path} complete. File metadata is stored inside {outputpath}")
    except:
        print(f'Error: Output folder "{outputpath}" cannot be written into. Please check the folder and try again.')

def generate_html_table(data, icons, directory):
    
    #check for file meta data
    try:
        with open(os.path.join(directory, "file_stat.json"), "rb") as file:
            content = json.load(file)
    except:
        print("Error: file_stats.json not found. Please check if path is a decompiled apk and try again.")
        content = {
            "File Size": "Cannot Be Found",
            "MD5": "Cannot Be Found",
            "Package Name": "Cannot Be Found"
        }
    #new version for multiple pages
    #scripts
    main_html = '<html><head><title>Flagged Results</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h555rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script></head>'
    #body creation with h-100 so that border can stretch
    main_html+='<body class="h-100">\n'
    
    #styles for main page
    main_html+='<style>\n'\
    '.card{\n'\
    '   border-radius: 4px;\n'\
    '   background: #fff;\n'\
    '   box-shadow: 0 6px 10px rgba(0,0,0,.08), 0 0 6px rgba(0,0,0,.05);\n'\
    '   transition: .3s transform cubic-bezier(.155,1.105,.295,1.12),.3s box-shadow,.3s -webkit-transform cubic-bezier(.155,1.105,.295,1.12);\n'\
    '   padding: 14px 80px 18px 36px;\n'\
    '   cursor: pointer;\n'\
    'border-width: 5px;\n'\
    'border-color: #fee8b5;\n'\
    '}\n'\
    '.card:hover{\n'\
    '    transform: scale(1.05);\n'\
    '    box-shadow: 0 10px 20px rgba(0,0,0,.12), 0 4px 8px rgba(0,0,0,.06);\n'\
    '}\n'\
    '.category_card{\n'\
    '    background: #fefce8;\n'\
    '}\n'\
    '.category_link {\n'\
    '   color: #3f248d;\n'\
    '   transition: .2s;\n'\
    '   text-decoration: none;\n'\
    '}\n'\
    '.category_link:hover {\n'\
    '    color:#696cff;\n'\
    '    text-decoration-color: #ffffff;\n'\
    '    cursor:pointer;\n'\
    '}\n'\
    '</style>\n'
    
    #main container to make the side bar and the main content horizontal
    main_html +='   <div class="container-fluid d-flex align-items-start p-0 h-100">\n'
    
    #metadata
    main_html +='       <div style="width:400px;" class="container-fluid border-end h-100">\n'
    #logo and name of application
    main_html +='           <div class="container pt-2 d-flex">\n'\
                '               <img style="width: 30px;height: 30px;" src="./malwhere.png">\n'\
                '               <h6>MalWhere</h6>\n'\
                '           </div>\n'
                
    main_html +='           <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">MetaData</h5>\n'
    for key,value in content.items():
        main_html +=f'           <h5 style="margin-left: 20px;" class="w-100"><p>{key}:</p><p class="text-wrap" style="color: #3f248d;">{value}<p></h5>\n'

    #category links
    main_html +='           <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">Category Links</h5>\n'
    for category, files in data.items():
        main_html +=f'           <h5 style="margin-left: 20px;color: #3f248d;" class="text-wrap w-100"><a class="category_link" href="./{category}.html">{" ".join(word[0].upper() + word[1:] for word in category.split())}</a></h5>\n'
    main_html +='       </div>\n'

    #main section with FYP group number and grid for cards
    main_html +='       <div class="container-fluid p-0 h-100">\n'\
                '           <h1 class="p-2 mb-0 border-bottom">FYP Group 6</h1>\n'\
                '           <div style="background-color:#f8fafc;" class="p-0 h-100">\n'\
                '               <div class="container-fluid ms-0 px-3">\n'\
                '               <h1 class="py-2 px-4">Categories</h1>\n'\
                '                   <div class="row row-cols-3 g-4">'
    #create cards for categories
    for category, files in data.items():
        main_html +='                   <div class="col">\n'\
                    '                       <div class="card category_card" style="height: 400px;">\n'\
                    '                           <div class="card-body">\n'\
                    f'                              {icons[category]}<h5 class="card-title">{" ".join(word[0].upper() + word[1:] for word in category.split())}</h5>\n'\
                    '                               <p class="card-text">Some quick example text to build on the card title and make up the bulk of the card\'s content.</p>\n'\
                    f'                               <a href="./{category}.html" class="btn btn-primary stretched-link">Go somewhere</a>\n'\
                    '                           </div>\n'\
                    '                       </div>\n'\
                    '                   </div>'

    try:
        output_filename = os.path.join(new_directory_name, f'main.html')
        with open(output_filename, 'w+', encoding="utf-8", errors='ignore') as flagged:
            flagged.write(main_html)
        print(f"Saved output as {output_filename}")
    except:
        print("error creating flagged_results.html. please check if path is a decompiled apk and try again.")

    for current_category, files in data.items():
        #scripts
        category_html = '<html><head><title>Flagged Results</title>\n'\
            '<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3" crossorigin="anonymous"></script>\n'\
            '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">\n'\
            '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.min.js" integrity="sha384-cuYeSxntonz0PPNlHhBs68uyIAVpIIOZZ5JqeqvYYIcEL727kskC66kF92t6Xl2V" crossorigin="anonymous"></script></head>\n'
            
        #body creation with h-100 so that border can stretch
        category_html += '<body class="h-100">\n'
    
        #styles for category
        category_html += '<style>\n'\
        '.category_link {\n'\
        '   color: #3f248d;\n'\
        '   transition: .2s;\n'\
        '   text-decoration:none;\n'\
        '}\n'\
        '.category_link:hover {\n'\
        '    color:#696cff;\n'\
        '    text-decoration-color: #ffffff;\n'\
        '    cursor:pointer;\n'\
        '}\n'\
        '.break-all {\n'\
        '   word-break:break-all;\n'\
        '}\n'\
        '</style>\n'

        #main containers
        category_html += '    <div class="container-fluid d-flex align-items-start p-0 h-100">\n'
        category_html += '        <div style="width:300px;color: #3f248d;" class="border-end h-100">\n'

        #$
        category_html += '          <div class="container pt-2 d-flex">\n'\
                        '              <img style="width: 30px;height: 30px;" src="./malwhere.png">'\
                        '              <h6>MalWhere</h6>'\
                        '          </div>'
        
        category_html += '          <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">MetaData</h5>\n'
        #generate metadata
        for key,value in content.items():
            main_html += f'          <h5 style="margin-left: 20px;color: #3f248d;" class="text-wrap w-100">{key}: {value}</h5>\n'
        category_html += '          <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">Category</h5>'
        #generate category links
        for category, files in data.items():
            #if current category place link back to main page 
            if (category == current_category):
                category_html += '          <h5 style="margin-left: 5px;color: #3f248d;" class="text-wrap w-100"><a href="./main.html"><div class=" d-flex align-items-center"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-caret-left" viewBox="0 0 16 16"><path d="M10 12.796V3.204L4.519 8zm-.659.753-5.48-4.796a1 1 0 0 1 0-1.506l5.48-4.796A1 1 0 0 1 11 3.204v9.592a1 1 0 0 1-1.659.753"/></svg>Back to Main Page</div></a></h5>'
            else:
                category_html += f'          <h5 style="margin-left: 20px;color: #3f248d;" class="text-wrap w-100"><a class="category_link" href="./{category}.html">{" ".join(word[0].upper() + word[1:] for word in category.split())}</a></h5>\n'
        category_html += '        </div>\n'
        #main body of html page for flagged strings
        category_html += '        <div class="container-fluid p-0 h-100">\n'\
                         '          <h1 class="p-2 mb-0 border-bottom">FYP Group 6</h1>\n'\
                         '          <div style="background-color:#f8fafc;" class="ps-1 h-100">\n'\
                         '              <div style="max-width: 2000px;" class="container-fluid ms-0">\n'\
                         f'                  <h1 class="py-2 px-4">{current_category}</h1>\n'

        if (current_category == "code_apis"):
            category_html += '                  <div class="accordion" id="accordionPanel">\n'
            for sub_category, files in data[current_category].items():
                category_html += '                      <div class="accordion-item">\n'
                category_html += f'                         <h2 class="accordion-header" id="sub-heading{sub_category.replace(" ", "")}">\n'
                category_html += f'                         <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_category.replace(" ", "")}" aria-expanded="false" aria-controls="sub-collapse{sub_category.replace(" ", "")}">{icons[sub_category]}{" ".join(word[0].upper() + word[1:] for word in sub_category.split())}</h2>\n'
                category_html += f'                         <div id="sub-collapse{sub_category.replace(" ", "")}" class="accordion-collapse collapse" aria-labelledby="sub-heading{sub_category.replace(" ", "")}" data-bs-parent="#accordionPanel">\n'
                category_html += '                              <div class="accordion-body">\n'
                category_html += '                                  <div class="container-fluid text-center "><div class="row"><div class="col-2 border py-3 break-all">File Name and Line Number</div><div class="col-6 border py-3 break-all">Details</div><div class="col-2 border py-3 break-all">Legitimate Use</div><div class="col-2 border py-3 break-all">Abuse</div></div>\n'
                for file_path, list_details in files.items():
                    file_name = Path(file_path).name
                    for detail in list_details:
                        category_html += f'                                 <div class="row"><div class="col-2 border py-3 break-all" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="right">{file_name}: Line {detail["line number"]}</div><div class="col-6 border py-3 break-all">{html.escape(detail["suspicious"])}</div ><div class="col-2 border py-3 break-all">{detail["legitimate"]}</div><div class="col-2 border py-3 break-all">{detail["abuse"]}</div></div>\n'
                category_html += '                                  </div>\n'
                category_html += '                              </div>\n'
                category_html += '                          </div>\n'
                category_html += '                      </div>\n'
            category_html += '                  </div>\n'
            #category_html += '                  <style>.accordion {--bs-accordion-btn-color: #ffffff;--bs-accordion-btn-bg:  #ffffff;--bs-accordion-active-color: #8ccd00;--bs-accordion-active-bg: #2a2a2a;} .accordion-button:after {background: #2a2a2a;} .accordion-button:not(.collapsed):focus {background: #2a2a2a; color:#fdfffc;}</style>\n'
        
        else:
            category_html += '                  <div class="container-fluid text-center "><div class="row"><div class="col-2 border py-3 break-all">File Name and Line Number</div><div class="col-6 border py-3 break-all">Details</div><div class="col-2 border py-3 break-all">Legitimate Use</div><div class="col-2 border py-3 break-all">Abuse</div></div>\n'
            for file_path, list_details in data[current_category].items():
                file_name = Path(file_path).name
                for detail in list_details:
                    category_html += f'                     <div class="row"><div class="col-2 border py-3 break-all" data-bs-toggle="tooltip" data-bs-title="{file_path}" data-bs-placement="right">{file_name}: Line {detail["line number"]}</div><div class="col-6 border py-3 break-all">{html.escape(detail["suspicious"])}</div><div class="col-2 border py-3 break-all">{detail["legitimate"]}</div><div class="col-2 border py-3 break-all">{detail["abuse"]}</div></div>\n'
            category_html += '                  </div>\n'

        category_html += '    </div>\n'
        category_html += "<script>let tooltipelements = document.querySelectorAll(\"[data-bs-toggle='tooltip']\");tooltipelements.forEach((el) => {new bootstrap.Tooltip(el);});</script>\n"
        category_html += '</body>'

        try:
            output_filename = os.path.join(new_directory_name, f'{current_category}.html')
            with open(output_filename, 'w+', encoding="utf-8", errors='ignore') as flagged:
                flagged.write(category_html)
            print(f"Saved output as {output_filename}")
        except:
            print(f"error creating {current_category}.html. please check if path is a decompiled apk and try again.")



    
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

def analyse_file(file_path, cwd, options, output):
    try:
        # print(f"Analysing {file_path}")
        result = rules.scan_file(file_path, cwd, options, output)
        # print(f"Successfully analysed {file_path}")
        return result
    except Exception as e:
        print(f"Error in analysing {file_path}: {e}")
        return {}

# def analyse_file(file_path, cwd, options, output):
#     try:
#         with open(file_path, 'rb') as file:
#             # raw_data = file.read()
#             # detected_encoding = chardet.detect(raw_data)['encoding']
#             raw_data = file.read(10000)
#         detected_encoding = chardet.detect(raw_data)['encoding']

#         if not detected_encoding:
#             detected_encoding = 'utf-8'

#         try:
#             with open(file_path, 'r', encoding=detected_encoding) as file:
#                 pass
#         except UnicodeDecodeError:
#             print(f"Unable to decode {file_path} with {detected_encoding} encoding.")

#         # print(f"Analysing {file_path}")
#         result = rules.scan_file(file_path, cwd, options, output)
#         # print(f"Successfully analysed {file_path}")
#         return result

#     except Exception as e:
#         print(f"Error in analysing {file_path}: {e}")
#         return {}

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
    # new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")

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

        description_categories = {
            "permissions": "Permissions that can be used for malicious activities. Permissions are required for most malicious activities, as most malicious APKs require some level of privilege to carry out their functions.",
            "url": "Urls can point to external servers that are being used as Command-and-Control servers or databases for malicious activities to exfiltrate data and receive information.",
            "code_apis": "This looks at different classes and methods commonly employed by APKs for activities such as sideloading and downloading external files.",
            "intents": "Intents allow the APK to both listen for intents broadcasted by other apps to hijack, as well as send their own intents to perform unauthorized actions.",
            "logging": "Logging of actions taken by the user or collection of sensitive logged data is dangerous",
            "extras": "Contains rules not fit for their own sections. Some rules look at identifying apps employing obfuscation methods to hide malicous methods for analysis as well as policies employed in older Android versions."
        }

        # identifier = get_identifier_from_path(directory)
        # new_directory_name = get_unique_directory_name(identifier, cwd)
        # new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")
        new_directory_name = time.strftime("%I-%M-%S %p %d-%m-%Y UTC+8") # with UTC+
        # new_directory_name = time.strftime("%I-%M-%S %p %d-%m-%Y") # without UTC

        new_directory_path = os.path.join(cwd, new_directory_name)
        os.makedirs(new_directory_path, exist_ok=True)
        shutil.copyfile('./icons/malwhere.png', new_directory_name+'/malwhere.png')
        json_create(new_directory_path)
        json_update(output, new_directory_path)
        try:
            with open("./icons/icons.json") as icons_json:
                icons = json.load(icons_json)
            
        except:
            print("error loading icons.json. Please check the file and ensure it is correct")
        generate_html_table(output, icons,args.path)
    elif args.subcommand == "modify-rules":
        update_rules()
