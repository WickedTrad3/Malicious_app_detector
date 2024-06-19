#!/usr/bin/env python3

import re
import os
from collections import defaultdict

# Existing suspicious patterns
suspicious_permissions = [
    "android.permission.READ_PHONE_STATE",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.READ_CALENDAR",
    "android.permission.CALL_PHONE"
]

suspicious_urls = [
    r"https?://[^\s]+",
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
]

suspicious_code_and_apis = [
    "COMMAND_SEND_SMS",
    "getIMEI",
    "httpclient1",
    "HttpPost",
    "UrlEncodedFormEntity",
    r"invoke-direct \{v6, v13\}, Lorg/apache/http/client/methods/HttpPost;-><init>\(Ljava/lang/String;\)V",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Ljavax/crypto/Cipher;->getInstance",
    "Landroid/content/ContentResolver;->query",
    "Landroid/hardware/Camera;->open",
    r"invoke-virtual \{.*\}, Ljava/lang/reflect/Method;->invoke",
    "requestWindowFeature",
    "PackageManager",
    "Calendar",
    "System",
    "sms",
    "click",
    "accessibility",
    "Android"
]

suspicious_policies = [
    "<force-lock />",
    "<wipe-data />",
    "<encrypted-storage />",
    "<limit-password />"
]

suspicious_intents = [
    "Intent",
    "mail",
    "sendto"
]

suspicious_logging = [
    "Log.v", "Log.d", "Log.i", "Log.w", "Log.e"
]

suspicious_extras = [
    "valueOf", "concat",
    "<force-lock />",
    "<wipe-data />",
    "<encrypted-storage />",
    "<limit-password />"
]

def flag_suspicious_permissions(content):
    permissions = re.findall(r"android\.permission\.\w+", content)
    return list([perm for perm in permissions if perm in suspicious_permissions])

def flag_suspicious_urls(content):
    flagged_urls = []
    for url_pattern in suspicious_urls:
        matches = re.findall(url_pattern, content)
        flagged_urls.extend(matches)
    return list(flagged_urls)

def flag_suspicious_code_and_apis(content):
    flagged_code_and_apis = []
    for snippet in suspicious_code_and_apis:
        matches = re.findall(".*?" + snippet+".*?\n", content)
        flagged_code_and_apis.extend(matches)
    flagged_code_and_apis = [intent.strip() for intent in flagged_code_and_apis]

    return list(flagged_code_and_apis)

def flag_suspicious_policies(content):
    return list([policy for policy in suspicious_policies if policy in content])

def flag_suspicious_logging(content):
    flagged_logging = []
    for log in suspicious_logging:
        matches = re.findall(".*?" + log +".*?\n", content)
        flagged_logging.extend(matches)
    return list(flagged_logging)

def flag_suspicious_intents(content):
    flagged_intents = []
    for intent in suspicious_intents:
        matches = re.findall(".*?" + intent+".*?\n", content, re.IGNORECASE)
        flagged_intents.extend(matches)
    flagged_intents = [intent.strip() for intent in flagged_intents]
    return list(flagged_intents)

def flag_suspicious_extras(content):
    flagged_extras = []
    for extra in suspicious_extras:
        matches = re.findall(".*?" + extra+".*?\n", content)
        flagged_extras.extend(matches)
    return list(flagged_extras)

def scan_file(file_path, scan_permissions, scan_urls, scan_code_and_apis, scan_logging, scan_intents, scan_extras):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        flagged_permissions = flag_suspicious_permissions(content) if scan_permissions else list()
        flagged_urls = flag_suspicious_urls(content) if scan_urls else list()
        flagged_code_and_apis = flag_suspicious_code_and_apis(content) if scan_code_and_apis else list()
        flagged_logging = flag_suspicious_logging(content) if scan_logging else list()
        flagged_intents = flag_suspicious_intents(content) if scan_intents else list()
        flagged_extras = flag_suspicious_extras(content) if scan_extras else list()

        return [flagged_permissions, flagged_urls, flagged_code_and_apis,
                flagged_logging, flagged_intents, flagged_extras]
    except:
        return [list(), list(), list(), list(), list(), list(), list()]
'''
def scan_folder(folder_path, scan_permissions, scan_urls, scan_code_and_apis, scan_policies, scan_logging, scan_intents, scan_extras):
    results = defaultdict(lambda: defaultdict(list))
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            (flagged_permissions, flagged_urls, flagged_code_and_apis,
             flagged_logging, flagged_intents, flagged_extras) = scan_file(
                file_path, scan_permissions, scan_urls, scan_code_and_apis, scan_policies,
                scan_logging, scan_intents, scan_extras)

            if flagged_permissions:
                results['permissions'][file_path].update(flagged_permissions)
            if flagged_urls:
                results['urls'][file_path].update(flagged_urls)
            if flagged_code_and_apis:
                results['code_and_apis'][file_path].update(flagged_code_and_apis)
            if flagged_logging:
                results['logging'][file_path].update(flagged_logging)
            if flagged_intents:
                results['intents'][file_path].update(flagged_intents)
            if flagged_extras:
                results['extras'][file_path].update(flagged_extras)

    return results

def print_results(results):
    for category, files in results.items():
        if category == 'permissions':
            print("\nFlagged Permissions:")
        elif category == 'urls':
            print("\nFlagged URLs:")
        elif category == 'code_and_apis':
            print("\nFlagged Code Snippets and APIs:")
        elif category == 'policies':
            print("\nFlagged Policies:")
        elif category == 'logging':
            print("\nFlagged Logging:")
        elif category == 'intents':
            print("\nFlagged Intents:")
        elif category == 'extras':
            print("\nFlagged Extras:")


        for file_path, items in files.items():
            print(f"  File: {file_path}")
            for item in items:
                print(f"    - {item}")
'''