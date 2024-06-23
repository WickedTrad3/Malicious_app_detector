#!/usr/bin/env python3

import re
import os
from collections import defaultdict

# Existing suspicious patterns with context
suspicious_permissions = [
    {
        "suspicious": "android.permission.READ_PHONE_STATE",
        "legitimate": "Allows read-only access to phone state, including the current cellular network information, the status of any ongoing calls, and a list of any PhoneAccounts registered on the device.",
        "abuse": "App may be using it to track device location, monitor calls, and gather other sensitive information"
    },
    {
        "suspicious": "android.permission.SEND_SMS",
        "legitimate": "Allows an application to send SMS messages.",
        "abuse": "App may be sending messages unknowingly for phishing or spam"
    },
    {
        "suspicious": "android.permission.READ_SMS",
        "legitimate": "Allows an application to read SMS messages.",
        "abuse": "App may be reading sensitive messages such as verification codes"
    },
    {
        "suspicious": "android.permission.WRITE_SMS",
        "legitimate": "(Obsolete, removed in API level 23) Allows an application to write SMS messages."
    },
    {
        "suspicious": "android.permission.RECORD_AUDIO",
        "legitimate": "Allows an application to record audio.",
        "abuse": "App may be recording audio without user consent"
    },
    {
        "suspicious": "android.permission.ACCESS_NETWORK_STATE",
        "legitimate": "Allows applications to access information about networks.",
        "abuse": "App may be checking if the device is connected to a network, which can be used to monitor network activity or data exfiltration"
    },
    {
        "suspicious": "android.permission.INTERNET",
        "legitimate": "Allows applications to open network sockets.",
        "abuse": "App may be communicating with a remote server"
    },
    {
        "suspicious": "android.permission.RECEIVE_BOOT_COMPLETED",
        "legitimate": "Allows an application to receive the Intent.ACTION_BOOT_COMPLETED that is broadcast after the system finishes booting.",
        "abuse": "App may launch itself after the device boots to ensure persistence"
    },
    {
        "suspicious": "android.permission.ACCESS_FINE_LOCATION",
        "legitimate": "Allows an app to access precise location.",
        "abuse": "App may be tracking the user's location"
    },
    {
        "suspicious": "android.permission.READ_CONTACTS",
        "legitimate": "Allows an application to read the user's contacts data.",
        "abuse": "App may be reading contacts for phishing or spamming"
    },
    {
        "suspicious": "android.permission.WRITE_EXTERNAL_STORAGE",
        "legitimate": "Allows an application to write to external storage.",
        "abuse": "App may be writing data to external storage for data theft or manipulation"
    },
    {
        "suspicious": "android.permission.CAMERA",
        "legitimate": "Required to be able to access the camera device.",
        "abuse": "App may be taking pictures or recording videos without user consent"
    },
    {
        "suspicious": "android.permission.READ_CALENDAR",
        "legitimate": "Allows an application to read the user's calendar data.",
        "abuse": "App may be reading calendar events which may contain sensitive information"
    },
    {
        "suspicious": "android.permission.CALL_PHONE",
        "legitimate": "Allows an application to initiate a phone call without going through the Dialer user interface for the user to confirm the call.",
        "abuse": "App may be initiating phone calls without user consent"
    }
]

suspicious_urls = [
    {
        "suspicious": r"https?://[^\s]+",
        "legitimate": "Indicates the presence of URLs.",
        "abuse": "App may be directing user to phishing sites, sideloading malware, or communicating with a C2 server."
    },
    {
        "suspicious": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "legitimate": "Indicates the presence of IP addresses.",
        "abuse": "App may be directing user to phishing sites, sideloading malware, or communicating with a C2 server."
    }
]

suspicious_code_and_apis = [
    {
        "suspicious": "COMMAND_SEND_SMS",
        "legitimate": "Used to send SMS messages.",
        "abuse": "App may be sending SMS messages"
    },
    {
        "suspicious": "getIMEI",
        "legitimate": "Retrieves the device's IMEI.",
        "abuse": "App may be using it for tracking or identifying the device"
    },
    {
        "suspicious": "httpclient1",
        "legitimate": "HTTP client usage.",
        "abuse": "App may be using it for communicating with remote servers"
    },
    {
        "suspicious": "HttpPost",
        "legitimate": "Used for sending data via HTTP POST method.",
        "abuse": "App may be sending data to a server, potentially for exfiltration of sensitive information"
    },
    {
        "suspicious": "UrlEncodedFormEntity",
        "legitimate": "Used in HTTP requests for sending data.",
        "abuse": "App may be sending data to a server"
    },
    {
        "suspicious": r"invoke-direct \{v6, v13\}, Lorg/apache/http/client/methods/HttpPost;-><init>\(Ljava/lang/String;\)V",
        "legitimate": "Indicates usage of HttpPost.",
        "abuse": "App may be using it for sending data to a server"
    },
    {
        "suspicious": "Landroid/telephony/SmsManager;->sendTextMessage",
        "legitimate": "Sends SMS messages.",
        "abuse": "App may be sending SMS messages"
    },
    {
        "suspicious": "Ljavax/crypto/Cipher;->getInstance",
        "legitimate": "Used for cryptographic operations.",
        "abuse": "App may be encrypting data, possibly for exfiltration or locking user device"
    },
    {
        "suspicious": "Landroid/content/ContentResolver;->query",
        "legitimate": "Queries data from content providers.",
        "abuse": "App may be querying data for theft"
    },
    {
        "suspicious": "Landroid/hardware/Camera;->open",
        "legitimate": "Opens the camera device.",
        "abuse": "App may be taking pictures or recording videos without user consent"
    },
    {
        "suspicious": r"invoke-virtual \{.*\}, Ljava/lang/reflect/Method;->invoke",
        "legitimate": "Indicates use of reflection.",
        "abuse": "App may be using reflection to dynamically invoke code, possibly for obfuscation"
    },
    {
        "suspicious": "requestWindowFeature",
        "legitimate": "Requests a window feature.",
        "abuse": "App may be mimicking system UI for phishing or capturing user input"
    },
    {
        "suspicious": "PackageManager",
        "legitimate": "Provides access to package information.",
        "abuse": "App may be stealing information about installed apps"
    },
    {
        "suspicious": "Calendar",
        "legitimate": "Accesses calendar data.",
        "abuse": "App may be accessing calendar events for sensitive information"
    },
    {
        "suspicious": "System",
        "legitimate": "General system usage.",
        "abuse": "Needs clarification"
    },
    {
        "suspicious": "sms",
        "legitimate": "Indicates SMS functionality.",
        "abuse": "General indication of SMS functions"
    },
    {
        "suspicious": "click",
        "legitimate": "Indicates click functionality.",
        "abuse": "General indication of clickjacking or simulating user clicks"
    },
    {
        "suspicious": "accessibility",
        "legitimate": "Indicates accessibility functionality.",
        "abuse": "Needs clarification"
    },
    {
        "suspicious": "Android",
        "legitimate": "General Android usage.",
        "abuse": "General Android flag"
    }
]

suspicious_intents = [
    {
        "suspicious": "Intent",
        "legitimate": "General intent usage.",
        "abuse": "General indication of intent usage"
    },
    {
        "suspicious": "mail",
        "legitimate": "Indicates mail functionality.",
        "abuse": "General indication of mail function"
    },
    {
        "suspicious": "sendto",
        "legitimate": "Indicates sending data.",
        "abuse": "May be used to send data out, potentially exfiltrating sensitive information."
    }
]

suspicious_logging = [
    {
        "suspicious": "Log.v",
        "legitimate": "Logging functions.",
        "abuse": "May be used to log sensitive information for exfiltration"
    },
    {
        "suspicious": "Log.d",
        "legitimate": "Logging functions.",
        "abuse": "May be used to log sensitive information for exfiltration"
    },
    {
        "suspicious": "Log.i",
        "legitimate": "Logging functions.",
        "abuse": "May be used to log sensitive information for exfiltration"
    },
    {
        "suspicious": "Log.w",
        "legitimate": "Logging functions.",
        "abuse": "May be used to log sensitive information for exfiltration"
    },
    {
        "suspicious": "Log.e",
        "legitimate": "Logging functions.",
        "abuse": "May be used to log sensitive information for exfiltration"
    }
]

suspicious_extras = [
    {
        "suspicious": "valueOf",
        "legitimate": "General usage.",
        "abuse": "Needs clarification"
    },
    {
        "suspicious": "concat",
        "legitimate": "General usage.",
        "abuse": "Needs clarification"
    },
    {
        "suspicious": "<force-lock />",
        "legitimate": "Locks the device.",
        "abuse": "App may lock the device for ransomware"
    },
    {
        "suspicious": "<wipe-data />",
        "legitimate": "Wipes device data.",
        "abuse": "App may wipe device data remotely for ransomware"
    },
    {
        "suspicious": "<encrypted-storage />",
        "legitimate": "Enforces encryption.",
        "abuse": "App may enforce encryption for ransomware"
    },
    {
        "suspicious": "<limit-password />",
        "legitimate": "Enforces password policies.",
        "abuse": "App enforces password policies, possibly to lock out user"
    }
]

def flag_suspicious_patterns(content, patterns):
    flagged_patterns = []
    for pattern in patterns:
        for match in re.finditer(pattern["suspicious"], content):
            line = content[match.start():content.find('\n', match.start())]
            flagged_patterns.append({
                "suspicious": line,
                "legitimate": pattern.get("legitimate", ""),
                "abuse": pattern.get("abuse", "")
            })
    return flagged_patterns

def scan_file(file_path, scan_permissions, scan_urls, scan_code_and_apis, scan_logging, scan_intents, scan_extras):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        content = content.decode('utf-8', errors='ignore')

        flagged_permissions = flag_suspicious_patterns(content, suspicious_permissions) if scan_permissions else list()
        flagged_urls = flag_suspicious_patterns(content, suspicious_urls) if scan_urls else list()
        flagged_code_and_apis = flag_suspicious_patterns(content, suspicious_code_and_apis) if scan_code_and_apis else list()
        flagged_logging = flag_suspicious_patterns(content, suspicious_logging) if scan_logging else list()
        flagged_intents = flag_suspicious_patterns(content, suspicious_intents) if scan_intents else list()
        flagged_extras = flag_suspicious_patterns(content, suspicious_extras) if scan_extras else list()

        return [flagged_permissions, flagged_urls, flagged_code_and_apis, flagged_logging, flagged_intents, flagged_extras]
    except Exception as e:
        print(f"Error: {e}")
        return [list(), list(), list(), list(), list(), list(), list()]
