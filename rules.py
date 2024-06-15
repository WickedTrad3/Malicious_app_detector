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
        self.flagged = {
            "permissions": [],
            "API": {
                "requestWindowFeature":[],
                "PackageManager": [],
                "Calendar":[],
                "System":[],
                "sms":[],
                "click":[],
                "accessibility":[]
            },
            "intent": [],
            "url": [],
            "functions":[
            ]
        }

    def check_strings(self, permissions_check, url_check, apis_check, extra_check):
        file_name,file_extension = self.file_name.split(".")
        if (file_name == "AndroidManifest" and permissions_check):
            self.check_permissions()
            #yet to seperate into different types of rule sets
            #intents
        if (file_extension == "java"):
            self.check_java(url_check, apis_check, extra_check)
    #change to flag a few permissions
    def check_permissions(self):
        self.is_flagged = True
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
    #how check if obfuscated
    #redo to map to cli
    #integrate intents into other section e.g url, api
    def check_java(self,url_check, apis_check, extra_check):
        intent_name = ""
        function_name = ""
        function_flagged = False
        open_brackets = 0
        close_brackets = 0
        is_function = False
        top_domain_name = [".xyz",'.live',".com",".store",".info",".top",".net"]
        with open(os.path.join(self.file_path, self.file_name), encoding="utf8") as fp:
            for line in fp:
                API= {
                "requestWindowFeature":[],
                "PackageManager": [],
                "splicing": [],
                "Calendar":[],
                "System":[],
                "sms":[],
                "click":[],
                "accessibility":[]
                },  
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
                    if (close_brackets == open_brackets and function_flagged):
                        self.flagged["functions"].append(function_name)
                        function_name = ""
                        self.is_flagged = True
                        function_flagged = False
                        is_function = False
                #flag for all?
                if ("Intent".lower() in line.lower()):
                    self.flagged["intent"].append(line.strip())
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
                elif ("http:".lower() in line.lower() and len(domainfound)):
                    self.flagged["url"].append(line.lstrip())
                    
                    function_flagged = True
                #sms, system, click need account for caps

                #requestWindowFeature
                #used to load other apps, and can be used to read info from other apps
                elif ("requestWindowFeature".lower() in line.lower()):
                    #self.flagged["API"]["requestWindowFeature"].append(line.strip())
                    API["requestWindowFeature"].append(line.strip())
                    function_flagged = True
                #flag calender
                elif ("Calendar" in line):
                    #self.flagged["API"]["Calendar"].append(line.strip())
                    API["Calendar"].append(line.strip())
                    function_flagged = True
                #flag system
                elif ("System".lower() in line.lower()):
                    #self.flagged["API"]["System"].append(line.strip())
                    API["System"].append(line.strip())
                    function_flagged = True
                elif ("sms".lower() in line.lower()):
                    #self.flagged["API"]["sms"].append(line.strip())
                    API["sms"].append(line.strip())
                    function_flagged = True
                
                elif ("click" in line):
                    #self.flagged["API"]["click"].append(line.strip())
                    API["click"].append(line.strip())
                    function_flagged = True
                #keylogging, dk if accessibility is correct
                elif ("accessbility".lower() in line.lower()):
                    #self.flagged["API"]["accessbility"].append(line.strip())
                    API["accessibility"].append(line.strip())
                    function_flagged = True
                elif ("PackageManager".lower() in line.lower()):
                    #self.flagged["API"]["PackageManager"].append(line.strip())
                    API["PackageManager"].append(line.strip())
                    function_flagged = True
                #check for splicing just in case values are semi obfuscated
                elif ("valueOf".lower() in line or "concat".lower() in line.lower()):
                    #self.flagged["API"]["splicing"].append(line.strip())
                    API["splicing"].append(line.strip())
                    function_flagged = True
                if (is_function):
                    function_name +=line.lstrip()
                #add sideloading

                #add writing of files/file access

                #not possible to detect sideloading without comparing apk to google play store
'''
    def Check_strings(self):
        with open(self.file_path+"\\"+self.file_name) as fp:
            if (self.rule_set == "permissions"):
                intent_found = False
                intent = ""
                for line in fp:
                    if ("permission" in line):
                        #json
                        self.flagged["suspicious_permissions"].append(line)
                    elif ("<intent" in line):
                        intent_found = True
                        intent+=line.strip()
                    elif ("</intent" in line):
                        intent_found = False
                        intent+=line.strip()
                        self.flagged["intent"] = intent
                        intent = ""
                    elif (intent_found):
                        intent+=line.strip()


            intent_name = ""
            if (self.rule_set == "Others"):
                for line in fp:
                    #look for all intents
                    if ("Intent" in line):
                         self.flagged["intent"].append(line)
                         intent_name = line.split("=")[0].split()[1]
                    #find where intent is being used in
                    elif (intent_name in line):
                        self.flagged["intent"].append(line)
                    #url may be in intent
                    elif ("http:" in line):
                        self.flagged["url"].append(line)
                    #request of permissions on api
                    #api
                    #store if private/pulic (function)
                    #if sus, flag, otherwise continue with function stored till next function
                    #if ()




                        

        


class File_read:
    def __init__(self, file_name, file_path, md5, rule_set):
    self.file_name = file_name
    self.file_path = file_path
    self.md5 = md5
    self.rule_set = rule_set
    '''