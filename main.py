#!/usr/bin/env python3
# python3 2.12.3
import os
from pathlib import Path
import rules
import json
import argparse
import sys
import subprocess
import itertools
import hashlib
import re
import base64
import html
import time
import shutil
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches 
import matplotlib.colors as mcolors
import seaborn as sns


def check_folders(directory, options):
    '''
    Checks iteratively through specified directory and executes analyse_file function on all files. Creates keys for the output dictionary.

    Parameters:
        directory (string): String of directory path
        cwd (string): String of current working directory

    Returns:
        output (dictionary): Dictionary of all flaggd strings
    '''
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
            print(f"Error reading {rule_path}, skipping...")
        except KeyError as e:
            print(f"Error reading {e}, skipping...")

    file_paths = []
    for path, folders, files in os.walk(directory):
        for filename in files:
            try:
                extension = filename.split(".")[1]
            except:
                extension = None
            if filename == "AndroidManifest.xml" or extension == "java" or extension == "smali":
                file_paths.append(os.path.join(path, filename))

    with ThreadPoolExecutor(max_workers=8) as executor:  # Adjust the number of workers as needed
        futures = {executor.submit(analyse_file, file_path, options, output): file_path for file_path in file_paths}
        for future in as_completed(futures):
            file_path = futures[future]
            try:
                result = future.result()
                output.update(result)
            except Exception as e:
                print(f"Error analysing {file_path}: {e}")

    return output

def create_output(ruleset, ruleset_name, output):
    '''
    creates key for ruleset.

    Parameters:
        ruleset (list): list of rules
        ruleset_name (string): name of ruleset
        output (dictionary): Dictionary of all flaggd strings

    Returns:
        output (dictionary): Dictionary of all flaggd strings
    '''
    output[ruleset_name] = {}
    for pattern in ruleset:
        if (ruleset_name =="code apis"):
            output[ruleset_name][pattern["category"]] = {}

    return output

def json_update(output, new_directory_path):
    '''
    updates the json file containing the flagged strings

    Parameters:
        output (dictionary): Dictionary of all flaggd strings
        new_directory_path (Path): Pathlib object of path that the analysis will be contained in

    Returns:
        null
    '''
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:
        json.dump(output, outfile, indent=1)

def json_create(new_directory_path):
    '''
    creates json file for containin the flagged strings

    Parameters:
        new_directory_path (Path): Pathlib object of path that the analysis will be contained in

    Returns:
        null
    '''
    with open(os.path.join(new_directory_path, "flagged_files.json"), "w+") as outfile:
        json.dump({}, outfile)

def decompile(apk_path, cwd, method, outputpath):
    '''
    Decompiles the APK based on the chosen method

    Parameters:
        apk_path (string): String of the directory of the specified APK
        cwd (string): String of current working directory
        method (string): String of the chosen language to be decompiled into (smali/java)
        outputpath (string): String of the directory to be outputted to

    Returns:
        null
    '''
    if outputpath is None:
            outputpath = cwd
    if (Path(outputpath).is_dir()):
        pass
    else:
        # print("Error: Output folder '"+args.output+"' not found. Please check the folder and try again.")
        print(f"Error: Output folder '{outputpath}' not found. Please check the folder and try again.")
        return

    if method == "java" and not os.path.isfile(os.path.join(cwd, "jadx/bin/jadx")):
        print("Error: JADX not found. Please check the path and try again.")
        return
    elif method == "smali" and not os.path.isfile(os.path.join(cwd, "apktool/apktool")):
        print("Error: APKTool not found. Please check the path and try again.")
        return
    try:
        if sys.platform == "linux" or sys.platform == "linux2":
            
            proc = subprocess.run([os.path.normpath(cwd + "/decompile.sh"), apk_path, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        elif sys.platform == "win32":
            process = subprocess.run([os.path.normpath(cwd + "/decompile.bat"), apk_path, outputpath, method], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # process = subprocess.Popen([os.path.normpath(cwd + "decompile.bat"), directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait()  # Wait for process to complete.
        #try:
        with open(apk_path, "rb") as file:
            content = file.read()
            
            digest = hashlib.md5(content)
            #content = content.decode('utf-8', errors='ignore')
        if (method == "java"):
            with open(Path(outputpath+"/jadx_decompiled/resources/AndroidManifest.xml"), "r", encoding="utf-8") as file:
                content = file.read()
            outputpath = outputpath+"/jadx_decompiled/"
        elif (method == "smali"):
            with open(Path(outputpath+"/apktool_decompiled/AndroidManifest.xml"), "r", encoding="utf-8") as file:
                content = file.read()
            outputpath = outputpath+"/apktool_decompiled/"
        package_name = re.findall(r'(package=\")(.*?)(\")', content)[0][1]
        #os.stat.st_size gives size of file in bytes, so conversion to megabytes is needed
        #times by 100 to make math.floor round down to nearest integer, then divide back by 100 to get back the original file size, rounded down by 2 decimal places
        stat = {
            "File Size": math.floor(os.stat(apk_path).st_size/1000000 * 100)/100,
            "MD5": digest.hexdigest(),
            "Package Name": package_name
        }
        outputpath = Path(outputpath)
        with open(outputpath / "file_stat.json", 'w') as outfile:
                json.dump(stat, outfile, indent=1)
        print(f"Decompilation of {apk_path} complete. File metadata is stored inside {outputpath.resolve()}")
        #except:
            #print(f'Error: Output folder "{outputpath}" cannot be written into. Please check if folder exists or permissions have been given to write into it and try again.')
    except FileNotFoundError as e:
        print(f"Error: File '{str(e)}' not found. Please check the file path and try again.")
    except PermissionError as e:
        print(f"Error: Permission denied when accessing '{str(e)}'. Please check your permissions and try again.")
    except KeyboardInterrupt:
        print(f"Error: Analysis of '{apk_path}' was interrupted.")
    except MemoryError:
        print(f"Error: Memory error occurred during decompilation of '{apk_path}'.")
    except Exception as e:
        print(f"Error: An unexpected error occurred during decompilation: {str(e)}")

def create_pie_chart(output_directory, data):
    '''
    Creates pie chart of the flagged strings of each category

    Parameters:
        output_directory (string): Pathlib object of path to be outputted to
        data (dictionary): Dictionary of all flaggd strings

    Returns:
        null
    '''
    sub_categories_apis_numbers = []
    main_catergories_numbers = []
    main_categories_label = []
    #outer_label = []
    sub_category_apis_label = []
    for category, files in data.items():
        main_categories_label.append(category)
        #outer_label.append(category)
        if category == "code apis":
            #outer_label.pop()
            
            main_catergories_numbers.append(0)
            for sub_category, files in data[category].items():
                sub_category_apis_label.append(sub_category)
                
                sub_categories_apis_numbers.append(0)
                for file in files:
                    sub_categories_apis_numbers[-1] += len(file)
                    main_catergories_numbers[-1] +=len(file)
        else:
            #count_per_outer.append(0)
            main_catergories_numbers.append(0)
            for file in files:
                #count_per_outer[-1] += len(file)
                main_catergories_numbers[-1] += len(file)
                
    fig, ax = plt.subplots()
    
    color_map = sns.color_palette("flare", as_cmap=True)
    colors =[color_map(i / len(main_categories_label)) for i in range(len(main_categories_label))]
    colors.reverse()
    patches, texts2 = plt.pie(main_catergories_numbers, colors=colors[:len(main_categories_label)],labels=main_categories_label, radius=1)
    my_circle=plt.Circle((0,0), 0.4, color='#fefce8')

    plt.gca().axis("equal")
    # Adding Circle in Pie chart
    fig.gca().add_artist(my_circle)
    sum_of_main_categories = sum(main_catergories_numbers)
    
    new_code_apis_label = [f'{" ".join(word[0].upper() + word[1:] for word in l.split())}, {s/sum_of_main_categories*100:0.2f}%' for l, s in zip(sub_category_apis_label, sub_categories_apis_numbers)]
    main_categories_label_percent = [f'{" ".join(word[0].upper() + word[1:] for word in l.split())}, {s/sum_of_main_categories*100:0.2f}%' for l, s in zip(main_categories_label, main_catergories_numbers)]
    
    lines = []
    index=0

    for main_category in main_categories_label_percent:
        #legend_label.append(main_categories_label_percent[index])
        lines.append(mpatches.Patch(color=colors[index], label=main_category))
        if (main_categories_label[index] == "code apis"):
            #legend_label.extend(new_code_apis_label)
            lines.extend([mpatches.Patch(color="none", label=sub_label, linewidth=3.0) for sub_label in new_code_apis_label])
        index+=1
        
    
        
    leg =ax.legend(handles= lines, bbox_to_anchor=(1.5,0.5), loc="right", frameon=False, bbox_transform=plt.gcf().transFigure)
    leg_list = [text for text in leg.get_texts()]
    for leg in leg_list:
        if leg.get_text() not in main_categories_label_percent:
            leg.set_fontsize('small')
        else:
           leg.set_fontsize('large') 

    #for t in texts1:
        #t.remove()
    for t in texts2:
        t.remove()
    
    plt.savefig(output_directory / "piechart.png", bbox_inches="tight",facecolor='#fefce8')

            

def generate_html_categories(data, icons, content, current_category, time_of_analysis):
    '''
    Generate html page of category

    Parameters:
        data (dictionary): Dictionary of all flaggd strings
        icons (dictionary): dictionary of the icons to embed into the html page
        current_category (string): String of the category being made
        time_of_analysis (string): String of the time of analysis

    Returns:
        null
    '''
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
    '.break-all {\n'\
    '   word-break:break-all;\n'\
    '}\n'\
    '.cat_link{text-decoration: none;}'\
    '.cat_link:hover{\n'\
    '    color:#696cff;\n'\
    '    text-decoration-color: #ffffff;\n'\
    '    cursor:pointer;\n'\
    '   background-color: #e0dced;\n'\
    '   transition: 1s;\n'\
    '}\n'\
    '</style>\n'

    #main containers
    category_html += '    <div class="container-fluid d-flex align-items-start p-0 h-100">\n'
    category_html += '       <div style="width:400px;" class="container-fluid d-flex h-100 p-0 flex-column justify-content-between">\n'
    
    category_html +='           <div class="px-2"><div class="container py-3 d-flex">\n'\
                '               <img style="width: 60px;height: 50;" src="./Malwhere_logo.png">\n'\
                '               <h2 class="fw-bold">MalWhere</h2></div>\n'
    #generate category links
    for category, files in data.items():
        #if current category place link back to main page 
        if (category == current_category):
            category_html += '          <a class="cat_link" href="./main.html"><h5 style="margin-left: 20px;" class="text-wrap py-2 rounded cat_link category_link"><div class=" d-flex align-items-center"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-caret-left" viewBox="0 0 16 16"><path d="M10 12.796V3.204L4.519 8zm-.659.753-5.48-4.796a1 1 0 0 1 0-1.506l5.48-4.796A1 1 0 0 1 11 3.204v9.592a1 1 0 0 1-1.659.753"/></svg>Back to Main Page</div></h5></a>'
        else:
            category_html += f'          <a class="cat_link" href="./{category}.html"><h5 style="margin-left: 20px;" class="text-wrap py-2 rounded cat_link category_link"><div class=" d-flex align-items-center">{icons[category]}{" ".join(word[0].upper() + word[1:] for word in category.split())}</div></h5></a>\n'
    category_html += '        </div>\n'
                
    
    #main_html +='           <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">MetaData</h5>\n'
    #metadata information
    #added time of analysis
    category_html+= '<div class="container-fluid py-2">'
    category_html +=f'           <div class="row"><div class="col-4 border border-4"><h6>Time Of Analysis: </h6></div><div class="col-8 border border-4"><h6 class="break-all" style="color: #3f248d;">{time_of_analysis}</h6></div></div>\n'
    
    for key,value in content.items():
        category_html +=f'           <div class="row"><div class="col-4 border border-4"><h6>{" ".join(word[0].upper() + word[1:] for word in key.split())}: </h6></div><div class="col-8 border-4 border"><h6 class="break-all" style="color: #3f248d;">{value}</h6></div></div>\n'
    category_html+='</div></div>\n'
    
    
    #main body of html page for flagged strings
    category_html += '       <div class="container-fluid p-0 border-start">\n'\
                    '       <h2 class="border-bottom p-2 m-0">FYP group 6</h2>'\
                    '           <div style="background-color:#f8fafc;" class="px-0 pt-4 h-100">\n'\
                        '              <div style="max-width: 2000px;" class="container-fluid ms-0">\n'\
                        f'                  <h1 class="py-2 px-4">{" ".join(word[0].upper() + word[1:] for word in category.split())}</h1>\n'

    if (current_category == "code apis"):
        category_html += '                  <div class="accordion" id="accordionPanel">\n'
        for sub_category, files in data[current_category].items():
            category_html += '                      <div class="accordion-item">\n'
            category_html += f'                         <h2 class="accordion-header" id="sub-heading{sub_category.replace(" ", "")}">\n'
            category_html += f'                         <button class="accordion-button collapsed" style="color: #3f248d;" type="button" data-bs-toggle="collapse" data-bs-target="#sub-collapse{sub_category.replace(" ", "")}" aria-expanded="false" aria-controls="sub-collapse{sub_category.replace(" ", "")}">{icons[sub_category]}{" ".join(word[0].upper() + word[1:] for word in sub_category.split())}</h2>\n'
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
    return category_html

def generate_html_table(data, icons, directory, output_directory, time_of_analysis, description_categories):
    '''
    Generate html of the main page

    Parameters:
        data (dictionary): Dictionary of all flaggd strings
        icons (dictionary): dictionary of the icons to embed into the html page
        current_category (string): String of the category being made
        time_of_analysis (string): String of the time of analysis
        description_categories (dictionary): Dictionary of the descriptions of the categories
    Returns:
        null
    '''
    #check for file meta data
    try:
        with open(Path(directory + "/file_stat.json"), "rb") as file:
            content = json.load(file)
    except Exception as e:
        print(f"Error with file_stat.json:{e}")
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
    main_html+='<link rel="stylesheet" media="screen" href="https://fontlibrary.org//face/rabbid-highway-sign-ii" type="text/css"/>'
    #styles for main page'       <div style="width:400px;" class="container-fluid  d-flex h-100 flex-column justify-content-between">\n'
    main_html+='<style>\n'\
    '.card{\n'\
    '   border-radius: 4px;\n'\
    '   background: #fff;\n'\
    '   box-shadow: 0 6px 10px rgba(0,0,0,.08), 0 0 6px rgba(0,0,0,.05);\n'\
    '   transition: .3s transform cubic-bezier(.155,1.105,.295,1.12),.3s box-shadow,.3s -webkit-transform cubic-bezier(.155,1.105,.295,1.12);\n'\
    '   padding: 14px 80px 18px 36px;\n'\
    '   cursor: pointer;\n'\
    'border-width: 5px;\n'\
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
    '.cat_link{text-decoration: none;}'\
    '.cat_link:hover{\n'\
    '    color:#696cff;\n'\
    '    text-decoration-color: #ffffff;\n'\
    '    cursor:poinGenerating main html pageter;\n'\
    '   background-color: #e0dced;\n'\
    'transition: 1s;\n'\
    '}\n'\
    '.break-all {\n'\
    '   word-break:break-all;\n'\
    '}\n'\
    '</style>\n'
    
    #main container to make the side bar and the main content horizontal
    main_html +='   <div class="container-fluid d-flex align-items-start p-0 h-100">\n'
    
    #metadata
    main_html +='       <div style="width:400px;" class="container-fluid d-flex h-100 p-0 flex-column justify-content-between">\n'
    #logo and name of application
    main_html +='           <div class="px-2"><div class="container py-3 d-flex">\n'\
                '               <img style="width: 60px;height: 50;" src="./Malwhere_logo.png">\n'\
                '               <h2 class="fw-bold">MalWhere</h2></div>\n'
    #category links
    #main_html +='           <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">Category Links</h5>\n'
    for category, files in data.items():
        main_html +=f'           <a class="cat_link" href="./{category}.html"><h5 style="margin-left: 20px;" class="text-wrap py-2 rounded cat_link category_link"><div class=" d-flex align-items-center">{icons[category]}{" ".join(word[0].upper() + word[1:] for word in category.split())}</div></h5></a>\n'
    main_html +='       </div>\n'
                
    
    #main_html +='           <h5 class="d-flex align-items-center lead"><hr width="20px" size="5">MetaData</h5>\n'
    #metadata information
    #added time of analysis
    main_html+= '<div class="container-fluid py-2" style="border-color:#3f248d;">'
    main_html +=f'           <div class="row"><div class="col-4 border border-4"><h6>Time Of Analysis: </h6></div><div class="col-8 border border-4"><h6 class="break-all" style="color: #3f248d;">{time_of_analysis}</h6></div></div>\n'
    
    for key,value in content.items():
        main_html +=f'           <div class="row"><div class="col-4 border border-4"><h6>{" ".join(word[0].upper() + word[1:] for word in key.split())}: </h6></div><div class="col-8 border-4 border"><h6 class="break-all" style="color: #3f248d;">{value}</h6></div></div>\n'
    main_html+='</div></div>\n'
    

    #main section with FYP group number and grid for cards
    main_html +='       <div class="container-fluid p-0 border-start">\n'\
                '       <h2 class="border-bottom p-2 m-0">FYP group 6</h2>'\
                '           <div style="background-color:#f8fafc;" class="px-0 pt-4 h-100">\n'\
                '               <div class="container-fluid ms-0 px-3">\n'
                #'               <h1 class="py-2 px-4">Categories</h1>\n'\
    main_html +='                   <div class="row row-cols-3 g-4 pt-5">'
    #create card for pie chart
    main_html +='                   <div class="col">\n'\
                '                       <div class="card category_card px-0" style="height:100%;width:100%;">\n'\
                '                           <div class="card-body px-0 h-100">\n'\
                f'                              <h5 class="card-title px-5"><a href="./main.html" class="border border-2 py-2 px-3 rounded-pill streched-link" style="text-decoration: none;color: #3f248d;border-color:#3f248d !important;">{icons[category]}Pie Chart of Categories</a></h5>\n'\
                f'                               <img class="img-fluid" src="{output_directory / "piechart.png"}">\n'\
                '                           </div>\n'\
                '                       </div>\n'\
                '                   </div>'
    #create cards for categories
    for category, files in data.items():
        main_html +='                   <div class="col">\n'\
                    '                       <div class="card category_card" style="height: 100%;width:100%;">\n'\
                    '                           <div class="card-body">\n'\
                    f'                              <h5 class="card-title"><a href="./{category}.html" class="border border-2 py-2 px-3 rounded-pill stretched-link" style="text-decoration: none;color: #3f248d;border-color:#3f248d !important;">{icons[category]}{" ".join(word[0].upper() + word[1:] for word in category.split())}</a></h5>\n'\
                    f'                               <p class="card-text pt-2">{description_categories[category]}</p>\n'\
                    '                           </div>\n'\
                    '                       </div>\n'\
                    '                   </div>'

    try:
        with open(output_directory / 'main.html', 'w+', encoding="utf-8", errors='ignore') as flagged:
            flagged.write(main_html)
        print(f"Saved output as {output_directory / 'main.html'}")

    except KeyboardInterrupt:
        print("Error creating main.html. Process cancelled by user.")
    except:
        print("error creating main.html. please check if path is a decompiled apk and try again.")

   
    with ThreadPoolExecutor(max_workers=8) as executor:  # Adjust the number of workers as needed
        futures = {executor.submit(generate_html_categories, data, icons, content, current_category, time_of_analysis): current_category for current_category in data.keys()}
        for future in as_completed(futures):
            current_category = futures[future]

            try:
                category_html = future.result()
                with open(output_directory / f'{current_category}.html', 'w+', encoding="utf-8", errors='ignore') as flagged:
                    flagged.write(category_html)
                print(f"Saved output as {output_directory / current_category}.html")
            except Exception as e:
                print(f"error creating {current_category}.html: {e}")



    
def load_json(file_path):
    '''
    Loads json file

    Parameters:
        file_path (string): String of file path

    Returns:
        json.load(file) (json): json object of file contents
    '''
    with open(file_path, 'r') as file:
        return json.load(file)

def save_json(file_path, data):
    '''
    Saves json data

    Parameters:
        file_path (string): String of file path
        data (dictionary): data to be saved into json file

    Returns:
        null
    '''
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
    
    if os.path.basename(file_path) == "code apis.json":
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
    '''
    Removes rule from ruleset

    Parameters:
        file_path (string): String of file path

    Returns:
        null
    '''
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
    '''
    Modifies rules from the malware

    Parameters:
        file_path (string): String of file path

    Returns:
        null
    '''
    data = load_json(file_path)
    suspicious = input("Enter the suspicious item to modify: ").strip()
    
    item_index = next((i for i, entry in enumerate(data) if entry['suspicious'].lower() == suspicious.lower()), None)
    
    if item_index is not None:
        print(f"Current rule: {data[item_index]}")
        new_suspicious = input("Enter the new suspicious item name (leave blank to keep current): ").strip()
        legitimate = input("Enter the new legitimate reasoning (leave blank to keep current): ").strip()
        abuse = input("Enter the new potential abuse (leave blank to keep current): ").strip()
        
        if os.path.basename(file_path) == "code apis.json":
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
    '''
    Modifies rules of the ruleset

    Parameters:

    Returns:
        null
    '''
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

def analyse_file(file_path, options, output):
    '''
    analyze the file and catch errors

    Parameters:
        file_path (string): String of file path
        options (dictionary): Dictionary of the options of the rulesets
        output (dictionary): Dictionary of all flaggd strings

    Returns:
        null
    '''
    try:
        if file_path.split(".")[-1] == "apk":
            print(f"Error: APK file '{file_path}' detected. Please decompile the APK first before analysis.")
            return {}
        # print(f"Analysing {file_path}")
        result = rules.scan_file(file_path, options, output)
        # print(f"Successfully analysed {file_path}")
        return result
    except FileNotFoundError as e: 
        print(f"Error: File '{str(e)}' not found. Please check the file path and try again.")
        return {}
    except PermissionError as e:
        print(f"Error: Permission denied when accessing '{str(e)}'. Please check your permissions and try again.")
        return {}
    except KeyboardInterrupt:
        print(f"Error: Analysis of '{file_path}' was interrupted.")
        return {}
    except MemoryError:
        print(f"Error: Memory error occurred during analysis of '{file_path}'.")
        return {}
    except UnicodeDecodeError:
        print(f"Error: Unable to decode '{file_path}'.")
        return {}
    except KeyError as e:
        print(f"Error: Unable to read file {str(e)}, not part of ruleset in options.")
        return {}
    except Exception as e:
        print(f"Error: An unexpected error occurred while analyzing '{file_path}': {str(e)}")
        return {}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="malwh", description="APK Analysis CLI Tool")
    
    subparsers = parser.add_subparsers(help='help for subcommand', required=True, dest="subcommand")
    # parser.add_argument("path", help="full path of the apk", type=str)

    parser_decompile = subparsers.add_parser('decompile', help='Decompile help')
    parser_decompile.add_argument('decompile_method', help='decompilation method between java and smali', choices=('java', 'smali'))
    parser_decompile.add_argument('-o', '--output', help='output directory for decompiled source code to be written into in either /jadx_decompiled or /apktool_decompiled, depending on the option specified. If not specified, the source code is written into the current working directory', type=str)
    parser_decompile.add_argument("path", help="full path of the apk", type=str)

    parser_analysis = subparsers.add_parser('analysis', help='Analysis help')
    parser_analysis.add_argument("-vv", "--very-verbose", help="Enable very verbose output for detailed analysis. Recommended to use after decompiling", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-p", "--permissions", help="Scan for permissions", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-u", "--urls", help="List all URLs found in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-a", "--apis", help="List all APIs used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-i", "--intents", help="List all intents used in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("-l", "--logging", help="List all logging done in the APK.", default=False, required=False, action="store_true")
    parser_analysis.add_argument("path", help="full path of the apk", type=str)

    parser_modify_rules = subparsers.add_parser('modify-rules', help='Modify JSON rules')

    args = parser.parse_args()
    cwd = os.path.dirname(__file__)
    non_verbose_mode = True
    # if not os.path.exists(args.path):
    #     print("Error: Folder/File '"+args.path+"' not found. Please check the path and try again.")
    #     sys.exit(1)
    
    if args.subcommand in ["decompile", "analysis"] and not os.path.exists(args.path):
        print(f"Error: Folder/File '{args.path}' not found. Please check the path and try again.")
        sys.exit(1)

    # identifier = get_identifier_from_path(args.path)
    # new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")

    if args.subcommand == "decompile":
        
        if (os.path.isfile(args.path) and args.path.split(".")[-1] == "apk"):
            decompile(args.path, cwd, args.decompile_method, args.output)
        
        else:
            # print("Error: File '"+args.path+"' not found. Please check the filename and try again.")
            print(f"Error: File '{args.path}' is not a valid APK file. Please check the filename and try again.")

    elif args.subcommand == "analysis":
        time_of_analysis = time.strftime("%I-%M-%S %p %d-%m-%Y UTC+8") # with UTC+
        if args.very_verbose:
            options = {
                "./rules/permissions.json":True,
                "./rules/url.json":True,
                "./rules/code apis.json":True,
                "./rules/intents.json":True,
                "./rules/logging.json":True,
            }
            output = check_folders(args.path, options)
            non_verbose_mode = False
        elif non_verbose_mode and (args.permissions or args.urls or args.apis or args.intents or args.logging):
            options = {
                "./rules/permissions.json":args.permissions,
                "./rules/url.json":args.urls,
                "./rules/code apis.json":args.apis,
                "./rules/intents.json":args.intents,
                "./rules/logging.json":args.logging,
            }
            output = check_folders(args.path, options)
        else:
            print("Invalid Command or Option:\nError: Invalid command or option specified. Use 'malwh --help' to see available commands and options.")

        description_categories = {
            "permissions": "Permissions that can be used for malicious activities. Permissions are required for most malicious activities, as most malicious APKs require some level of privilege to carry out their functions.",
            "url": "Urls can point to external servers that are being used as Command-and-Control servers or databases for malicious activities to exfiltrate data and receive information.",
            "code apis": "This looks at different classes and methods commonly employed by APKs for activities such as sideloading and downloading external files.",
            "intents": "Intents allow the APK to both listen for intents broadcasted by other apps to hijack, as well as send their own intents to perform unauthorized actions.",
            "logging": "Logging of actions taken by the user or collection of sensitive logged data is dangerous",
        }

        # identifier = get_identifier_from_path(directory)
        # new_directory_name = get_unique_directory_name(identifier, cwd)
        # new_directory_name = time.strftime("%H-%M-%S-%d-%m-%Y")
        
        # new_directory_name = time.strftime("%I-%M-%S %p %d-%m-%Y") # without UTC
        try:
            new_directory_path = Path(cwd, time_of_analysis)
            os.makedirs(new_directory_path, exist_ok=True)
            shutil.copyfile(Path('./icons/Malwhere_logo.png'), new_directory_path / 'Malwhere_logo.png')
            json_create(new_directory_path)
            json_update(output, new_directory_path)
            try:
                with open(Path("./icons/icons.json")) as icons_json:
                    icons = json.load(icons_json)
                
            except:
                print("error loading icons.json. Please check the file and ensure it is correct")
            generate_html_table(output, icons,args.path, new_directory_path, time_of_analysis, description_categories)
            create_pie_chart(new_directory_path, output)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif args.subcommand == "modify-rules":
        update_rules()
