import json

class File_read:
    #havent decided wether to make this one class for all files or one for each file
    #leaning to one class per folder
    #need check for libraries
    def __init__(self, file_name, file_path):
        self.file_name = file_name
        self.file_path = file_path
        #unknown if need md5
        self.md5 = ""
        self.name_suspicious = False
        self.flagged = {
            "name":self.file_name,
            "suspicious_permissions": [],
            "API": [],
            "intent": [],
            "url": [],
            "functions":[]
        }

    def check_rule_set(self):
        file_name,file_extension = self.file_name.split(".")
        
        if (file_extension == "xml"):
            if (file_name == "AndroidManifest"):
                self.check_permissions()
            #yet to seperate into different types of rule sets
            #intents
        if (file_extension == "java"):
            self.check_java()

    def check_permissions(self):
        with open(self.file_path+"\\"+self.file_name) as fp:
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

    def check_java(self):
        intent_name = ""
        function_name = ""
        function_flagged = False
        open_brackets = 0
        close_brackets = 0
        top_domain_name = [".xyz",'.live',".com",".store",".info",".top",".net"]
        with open(self.file_path+"\\"+self.file_name) as fp:
            for line in fp:
                domainfound = [element for element in top_domain_name if element in line]
                #look for all intents
                if ("{" in line):
                    open_brackets +=1
                if ("}" in line):
                    close_brackets +=1
                    if (close_brackets == open_brackets and function_flagged):
                        self.flagged["functions"].append(function_name)
                        function_name = ""
                        function_flagged = False
                if ("Intent" in line):
                    self.flagged["intent"].append(line)
                    intent_name = line.split("=")[0].split()[1]
                    function_name +=""
                    function_flagged = True
                #find where intent is being used in
                elif (intent_name in line):
                    self.flagged["intent"].append(line)
                    function_flagged = True
                #url may be in intent
                #only obtains if directly http
                #other methods include json strings and piecing together
                #DGA can be done to generate its own domain name to access
                #.xyz,.live,.com,.store,.info,.top,.net
                elif ("http:" in line and len(domainfound)):
                    self.flagged["url"].append(line)
                #requestWindowFeature
                #used to load other apps, and can be used to read info from other apps
                elif ("requestWindowFeature" in line):
                    function_flagged = True
                #flag calender
                elif ("Calendar" in line):
                    function_flagged = True
                #flag system

                #find where permissions are being used
                elif ("" in line):
                    

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