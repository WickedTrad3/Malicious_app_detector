#!/usr/bin/env python3

import re
import os
import sys
import argparse
from collections import Counter, defaultdict

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

suspicious_code = [
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
    r"invoke-virtual \{.*\}, Ljava/lang/reflect/Method;->invoke"
]

suspicious_policies = [
    "<force-lock />",
    "<wipe-data />",
    "<encrypted-storage />",
    "<limit-password />"
]

def flag_suspicious_permissions(content):
    permissions = re.findall(r"android\.permission\.\w+", content)
    return set([perm for perm in permissions if perm in suspicious_permissions])

def flag_suspicious_urls(content):
    flagged_urls = []
    for url_pattern in suspicious_urls:
        matches = re.findall(url_pattern, content)
        flagged_urls.extend(matches)
    return set(flagged_urls)

def flag_suspicious_code(content):
    flagged_code = []
    for snippet in suspicious_code:
        matches = re.findall(snippet, content)
        flagged_code.extend(matches)
    return set(flagged_code)

def flag_suspicious_policies(content):
    return set([policy for policy in suspicious_policies if policy in content])

def scan_file(file_path, scan_permissions, scan_urls, scan_code, scan_policies):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

        flagged_permissions = flag_suspicious_permissions(content) if scan_permissions else set()
        flagged_urls = flag_suspicious_urls(content) if scan_urls else set()
        flagged_code = flag_suspicious_code(content) if scan_code else set()
        flagged_policies = flag_suspicious_policies(content) if scan_policies else set()

        return flagged_permissions, flagged_urls, flagged_code, flagged_policies
    except:
        return set(), set(), set(), set()

def scan_folder(folder_path, scan_permissions, scan_urls, scan_code, scan_policies):
    results = defaultdict(lambda: defaultdict(set))
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            flagged_permissions, flagged_urls, flagged_code, flagged_policies = scan_file(
                file_path, scan_permissions, scan_urls, scan_code, scan_policies)

            if flagged_permissions:
                results['permissions'][file_path].update(flagged_permissions)
            if flagged_urls:
                results['urls'][file_path].update(flagged_urls)
            if flagged_code:
                results['code'][file_path].update(flagged_code)
            if flagged_policies:
                results['policies'][file_path].update(flagged_policies)

    return results

def print_results(results):
    for category, files in results.items():
        if category == 'permissions':
            print("\nFlagged Permissions:")
        elif category == 'urls':
            print("\nFlagged URLs:")
        elif category == 'code':
            print("\nFlagged Code Snippets:")
        elif category == 'policies':
            print("\nFlagged Policies:")

        for file_path, items in files.items():
            print(f"  File: {file_path}")
            for item in items:
                print(f"    - {item}")

def main():
    usage = """Usage: malwh [options] <folder_path>

To make this script executable and run it as 'malwh', use the following commands:
chmod +x malwh.py
mv malwh.py /usr/local/bin/malwh
"""

    parser = argparse.ArgumentParser(description="Scan files for suspicious content.", usage=usage)
    parser.add_argument("folder_path", nargs='?', help="Path to the folder to scan")
    parser.add_argument("-vv", action="store_true", help="Verbose output for everything")
    parser.add_argument("-p", action="store_true", help="Scan for permissions")
    parser.add_argument("-u", action="store_true", help="Scan for URLs")
    parser.add_argument("-a", action="store_true", help="Scan for API calls")
    parser.add_argument("-i", action="store_true", help="Scan for policies")

    args = parser.parse_args()

    if not args.folder_path:
        print(usage)
        parser.print_help()
        sys.exit(1)

    if args.vv:
        scan_permissions = scan_urls = scan_code = scan_policies = True
    else:
        scan_permissions = args.p
        scan_urls = args.u
        scan_code = args.a
        scan_policies = args.i

    results = scan_folder(args.folder_path, scan_permissions, scan_urls, scan_code, scan_policies)
    print_results(results)

if __name__ == "__main__":
    main()