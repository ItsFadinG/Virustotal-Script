from __future__ import print_function
import requests
import re
import sys

# Validate the user input:
def get_input():
    if len(sys.argv) <= 1:
        print("[+] Usage: python3 Virustotal_checker.py [URL or Domain or IP or file Hash]")
        sys.exit(1)
    else:
        return sys.argv[1]
get_input()

API = "Enter Your API" 	# Add Your API key Here

# Search by domain:
def DOMAIN_search():
    domain_name = sys.argv[1]
    DOMAIN_REGEX = re.search(r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$", domain_name)
    if DOMAIN_REGEX:
        url = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={0}&domain={1}".format(API, domain_name)
        print("Domain being queried: {}".format(url))
        response = requests.get(url)
        print(response.json())
DOMAIN_search()

# Search by IP:
def IP_search():
    IP = (sys.argv[1])
    IP_REGEX = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", IP)
    if IP_REGEX:
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={0}&ip={1}".format(API,IP)
        print("IP being queried: {}".format(url))
        response = requests.get(url)
        print(response.json())
        sys.exit(1)
IP_search()

# Search by URL:
def URL_search():
    URL = (sys.argv[1])
    URL_REGEX = re.search(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)", URL)
    if URL_REGEX:
        url = "https://www.virustotal.com/vtapi/v2/url/report?apikey={0}&resource={1}".format(API, URL)
        print("URL being queried: {}".format(url))
        response = requests.get(url)
        print(response.json())
        sys.exit(1)
URL_search()
 
# Search by Hash:

def Hash_search():
    try:
        Hash = (sys.argv[1])
        if len(Hash) == 32 or len(Hash) == 40 or len(Hash) == 64 or len(Hash) == 128:
            url = "https://www.virustotal.com/vtapi/v2/file/report?apikey={0}&resource={1}".format(API, Hash)
            print("Hash being queried: {}".format(url))
            response = requests.get(url)
            print(response.json())
        else:
            print("your hash does not appear to be valid.")
            sys.exit(1)
    except Exception:
        print ('There is something wrong with your hash \n' + Exception)
Hash_search()
