# A python script for quick IP IoC Hunting; building on my old powershell one
# Authored by: Nicholas Roddy; @RoddSec

# Import packages
import os
from pprint import pprint
import json
import pyperclip as pc
import requests

def gn_data(tag, size):
    # Instantiate the URL + the specific gn query
    url = "https://api.greynoise.io/v2/experimental/gnql?query=last_seen:1d classification:malicious tags:" + tag + "&size=" + size

    # Instantiate the headers
    headers = {
        "accept" : "application/json",
        "key": os.environ.get('gnkey')
    }
    
    # Gets the API response, converts to json, and establishes new variables for formatting
    response = requests.get(url, headers=headers)
    
    json_response = response.json()
    jdata = json_response['data']
    ipval = None
    ipdat = []

   # Iterates through the json data and filters all ip values to a new array
    if isinstance (jdata, list):
        for i in jdata:
            if isinstance(i, dict) and 'ip' in i:
                ipval = i['ip']
                ipdat.append(ipval)
    
    # Pushes new array created in the for loop above off to be built for a defender query 
    defender_query(ipdat)
    
def defender_query(ipdat):

    # Import IPs
    ip_list = (ipdat)

    # Initialize empty array for the for loop
    final_val = []

    # Formats ip_list data to be closer to a Defender query
    for i in range(len(ip_list)):
        tmp_val = '"' + ip_list[i] + '"'
        final_val.append(tmp_val)

    # Converts array to string and allows for more formatting for Defender
    # Also this drops the final comma at the end for further formatting
    temp_array = ', '.join(final_val)
    temp_array = temp_array.rstrip(',')

    # This is the Defender query
    def_data = "DeviceNetworkEvents \n| where RemoteIP in (" + temp_array + ")"

    # Writes Defender query to clipboard 
    pc.copy(def_data)


#calls the main prgrm
tag = input("What tag would you like to query:")
size = input("How large of a query? (The limit is 10k):")
gn_data(tag, size)
