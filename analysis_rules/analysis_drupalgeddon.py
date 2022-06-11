import re
import json
from sys import argv, path
path.insert(0, '/media/shubham/Shubham/Learning/CyFI/Pre/Jedi')
from constants.jedi_constants import *
from models.base_analysis_class import BaseAnalysisClass
from models.base_class import PluginFile

class Analysis_Drupalgeddon(BaseAnalysisClass):
    def __init__(self):
        self.pattern0 = re.compile(r'\w+\.projecthoneypot\.org')
        self.pattern1 = re.compile(r'my_sucuri_encoding') # Legit sucuri file that looks like bad file

        self.pattern2 = re.compile(r'/\*[a-z0-9]+\*/') # /*435345352*/ pattern 
        
        self.pattern3 = re.compile(r'@?eval[\s\(]*base64_decode[\s\(]*')
        
        self.pattern4 = re.compile(r'aWYobWQ1KCRfUE9TVFsicGYiXSkgPT09ICI5M2FkMDAzZDdmYzU3YWFlOTM4YmE0ODNhNjVkZGY2ZCI') # The md5 check pattern b64 encoded, corresponding to pattern6 when decoded
        self.pattern5 = re.compile(r'R2a2Z1PWZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwOi8vbm9ydHN') # Part of b64 which when decoded gives the download URL
        
        # Patterns in the decoded b64 data, sometimes files are seen to not be b64 encoded
        self.pattern6 = re.compile(r'md5[\s\()]*\$_POST[\s\[]*.*=+ \"93ad003d7fc57aae938ba483a65ddf6d\"') # commonly seen md5 hash check in drupalgeddon attacks
        self.pattern7 = re.compile(r'if\(\$patchedfv[\s]*=+') # checking patch status
        
        self.pattern8 = re.compile(r'file_get_contents[\s\(]')
        self.pattern9 = re.compile(r'http:\/\/nortservis\.net\/session\.php\?id') # malicious URL

    def reprocessFile(self, pf_obj, r_data):
        # Check if file contents have Drupalgeddon payload
        p0 = re.findall(self.pattern0, r_data)              # Avoid files from Project Honeypot
        p1 = re.findall(self.pattern1, r_data)              # Legit files
        p2 = re.findall(self.pattern2, r_data)              # Comments with numbers
        p3 = re.findall(self.pattern3, r_data)              # b64 decode, then eval
        p4 = re.findall(self.pattern4, r_data)              # md5 check b64 encoded
        p5 = re.findall(self.pattern5, r_data)              # b64 encoded part of one of the URLs of the improved payload
        p6 = re.findall(self.pattern6, r_data)              # b64 decoded md5 check
        p7 = re.findall(self.pattern7, r_data)              # Checking server patch status
        p8 = re.findall(self.pattern8, r_data)              # Getting file from remote server - part of improved payload
        p9 = re.findall(self.pattern9, r_data)              # One of the file URLs of the improved payload

        if ((p2 and p3 and p4) or (p2 and p3 and p4 and p5) 
        or (p2 and p6) or (p2 and p6 and p7) or (p2 and p6 and p7 and p8 and p9)) and (len(p0)==0):
            pf_obj.suspicious_tags.append("DLGD")
            pf_obj.extracted_results["DLGD"] = [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9]
        elif p6:
            if ((p4 or p6) and (len(p0)==0) and (len(p1)==0)):
                pf_obj.suspicious_tags.append("DLGD")
                pf_obj.extracted_results["DLGD"] = [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9]
        else:
            if "DLGD" in pf_obj.suspicious_tags:
                pf_obj.suspicious_tags.remove("DLGD")
       


if __name__=='__main__':  # for debug only
  path.insert(0, '/media/shubham/Shubham/Learning/CyFI/Pre/Jedi')
  from models.base_class import PluginFile
  pf_obj = PluginFile(argv[1], 'A', ['php'], 'TEST_PLUGIN')
  with open(pf_obj.filepath, 'r', errors="ignore") as f:
    r_data = f.read()

  analysis = Analysis_Drupalgeddon()
  analysis.reprocessFile(pf_obj, r_data)

  if len(pf_obj.suspicious_tags):
    pf_obj.is_malicious = True
  else:
    pf_obj.is_malicious = False

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(pf_obj.plugin_name))
  print('State:       {}'.format(pf_obj.state))
  print('Mime Type:   {}'.format(pf_obj.mime_type))
  print('Tags:        {}'.format(pf_obj.suspicious_tags))
  print('Malicious:   {}'.format(pf_obj.is_malicious))
  print('Extracted Results: ')
  print(json.dumps(pf_obj.extracted_results, indent=2))
  print()
