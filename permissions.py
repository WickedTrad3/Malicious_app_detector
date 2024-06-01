class File_read:
    #havent decided wether to make this one class for all files or one for each file
    #leaning to one class per folder
    def __init__(self, file_name, file_path, md5, rule_set, name_suspicious):
        self.file_name = file_name
        self.file_path = file_path
        self.md5 = md5
        self.rule_set = rule_set
        self.name_suspicious = False

    def check_rule_set(self):
        file_extension = self.file_name.split(".")
        if (file_extension[-1]):
            if (self.file_name == "AndroidManifest"):
                self.rule_set == "permissions"
            else:
                self.rule_set == "intents"


    def Check_strings(self):
        if (self.rule_set == "permissions"):
            

        

def check_folders():
'''
class File_read:
    def __init__(self, file_name, file_path, md5, rule_set):
    self.file_name = file_name
    self.file_path = file_path
    self.md5 = md5
    self.rule_set = rule_set
    '''