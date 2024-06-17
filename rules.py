import json
import javalang
import os
#dont care about false positives
#narrow intent - (low prio)
class File_read:
    #havent decided wether to make this one class for all files or one for each file
    #leaning to one class per folder
    #need check for libraries
    def __init__(self, file_name, file_path):
        self.file_name = file_name
        self.file_path = file_path
        #unknown if need md5
        self.md5 = ""
        self.is_flagged = False
        #perms
        #api -> asking of perms to external apps/display features?
        #api -> more than just package names and system calls?
        self.flagged = {
            "permissions": [],
            "API": {
                #api
                "requestWindowFeature":[],
                #package
                "PackageManager": [],
                #calender is api
                "Calendar":[],
                "System":[],
                "sms":[],
                "click":[],
                "accessibility":[],
                "Android":[]
            },
            "logging": [],
            "intent": {
                "email":[],
                "others":[]
            },
            #rename to internet use
            #add use of 
            "url": [],
            "extra": [],
            "functions":[]
        }

    def check_strings(self, permissions_check, url_check, apis_check, intent_check, logging_check, extra_check):
        file_name,file_extension = self.file_name.split(".")
        if (file_name == "AndroidManifest" and permissions_check):
            self.check_permissions()
            #yet to seperate into different types of rule sets
            #intents
        if (file_extension == "java"):
            self.check_java(url_check, apis_check, intent_check, logging_check, extra_check)
    #change to flag a few permissions
    def check_permissions(self):
        
        with open(os.path.join(self.file_path, self.file_name), encoding="utf8") as fp:
            intent_found = False
            intent = ""
            #copy from amadeus
            sus_perms = ["READ_PHONE_STATE", 
                         "SEND_SMS", 
                         "READ_SMS", 
                         "WRITE_SMS", 
                         "RECORD_AUDIO", 
                         "ACCESS_NETWORK_STATE",
                         "INTERNET",
                         "RECEIVE_BOOT_COMPLETED", 
                         "ACCESS_FINE_LOCATION",
                         "READ_CONTACTS",
                         "WRITE_EXTERNAL_STORAGE",
                         "CAMERA",
                         "READ_CALENDAR",
                         "CALL_PHONE"
                         ]
            for line in fp:
                perms_found = [element for element in sus_perms if element.lower() in line.lower()]
                if ("permission" in line):
                    #json
                    if (len(perms_found)==0):
                        self.flagged["permissions"].append(line)
                        self.is_flagged = True
                elif ("<intent" in line):
                    intent_found = True
                    intent+=line.strip()
                elif ("</intent" in line):
                    intent_found = False
                    intent+=line.strip()
                    self.flagged["intent"].append(intent)
                    intent = ""
                elif (intent_found):
                    intent+=line.strip()
                    self.is_flagged = True
    #how check if obfuscated
    #redo to map to cli
    #integrate intents into other section e.g url, api
    def check_java(self, url_check, apis_check, intent_check, logging_check, extra_check):
        intent_list = []
        function_name = ""
        function_flagged = False
        not_email_intent_bool = True
        open_brackets = 0
        close_brackets = 0
        is_function = False
        top_domain_name = [".xyz",'.live',".com",".store",".info",".top",".net"]
        with open(os.path.join(self.file_path, self.file_name), encoding="utf8") as fp:
            for line in fp:
                domainfound = [element for element in top_domain_name if element.lower() in line.lower()]
                #look for all intents
                #does not account for intents existing outside method
                if ("{" in line and "class" not in line):
                    open_brackets +=1
                    is_function = True
                if ("}" in line):
                    close_brackets +=1
                    function_name +=line.strip()
                    if (close_brackets == open_brackets):
                        is_function = False
                        not_email_intent_bool = True
                    if (close_brackets == open_brackets and function_flagged):
                        self.flagged["functions"].append(function_name)
                        function_name = ""
                        self.is_flagged = True
                        function_flagged = False
                        is_function = False
                        
                        if (not_email_intent_bool == False):
                            self.flagged["intent"]["mail"].extend(intent_list)
                            not_email_intent_bool = True
                #flag for all?
                if ("Intent".lower() in line.lower() and intent_check):
                    

                    if ("mail".lower() in line.lower() or "sendto".lower() in line.lower()):
                        #self.flagged["intent"]["mail"].append(line.strip())
                        intent_list.append(line.strip())
                        not_email_intent_bool =False
                    elif (not_email_intent_bool):
                        self.flagged["intent"]["others"].append(line.strip())
                        
                    #intent_name = line.split("=")[0].split()[1]
                    if (is_function):
                        function_flagged = True
                #find where intent is being used in
                #elif (intent_name in line and intent_name !=""):
                    #self.flagged["intent"].append(line)
                    #function_flagged = True
                #url may be in intent
                #only obtains if directly http
                #other methods include json strings and piecing together
                #DGA can be done to generate its own domain name to access
                #.xyz,.live,.com,.store,.info,.top,.net
                #wget,
                #try get hierachy of permissions used for url usage
                # under internet -> HttpURLConnection, java.net.URL, OkHttp, RetroFit
                # fix url, cannot detect github
                #domain found may not be working
                if ("http:".lower() in line.lower() and len(domainfound) and url_check):
                    self.flagged["url"].append(line.lstrip())
                    
                    function_flagged = True
                #sms, system, click need account for caps
                if (apis_check):
                #requestWindowFeature
                #used to load other apps, and can be used to read info from other apps
                    if ("requestWindowFeature".lower() in line.lower()):
                        self.flagged["API"]["requestWindowFeature"].append(line.strip())
                        #API["requestWindowFeature"].append(line.strip())
                        function_flagged = True
                    #flag calender
                    elif ("Calendar" in line):
                        self.flagged["API"]["Calendar"].append(line.strip())
                        #API["Calendar"].append(line.strip())
                        function_flagged = True
                    #flag system
                    elif ("System".lower() in line.lower()):
                        self.flagged["API"]["System"].append(line.strip())
                        #API["System"].append(line.strip())
                        function_flagged = True
                    elif ("sms".lower() in line.lower()):
                        self.flagged["API"]["sms"].append(line.strip())
                        #API["sms"].append(line.strip())
                        function_flagged = True
                    
                    elif ("click" in line):
                        self.flagged["API"]["click"].append(line.strip())
                        #API["click"].append(line.strip())
                        function_flagged = True
                    #keylogging, dk if accessibility is correct
                    elif ("accessbility".lower() in line.lower()):
                        self.flagged["API"]["accessbility"].append(line.strip())
                        #API["accessibility"].append(line.strip())
                        function_flagged = True
                    elif ("PackageManager".lower() in line.lower()):
                        self.flagged["API"]["PackageManager"].append(line.strip())
                        #API["PackageManager"].append(line.strip())
                        function_flagged = True
                    #flag all android activities
                    elif ("Android".lower() in line):
                        self.flagged["API"]["Android"].append(line.strip())
                        function_flagged = True
                if ("log".lower() in line and logging_check):
                        self.flagged["logging"].append(line.strip())
                        function_flagged = True
                if (extra_check):
                    #check for splicing just in case values are semi obfuscated
                    if ("valueOf".lower() in line or "concat".lower() in line.lower()):
                        self.flagged["extra"].append(line.strip())
                        #API["splicing"].append(line.strip())
                        function_flagged = True
                    
                
                if (is_function):
                    function_name +=line.lstrip()
                #add sideloading

                #add writing of files/file access

                #not possible to detect sideloading without comparing apk to google play store