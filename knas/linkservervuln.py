#!/usr/bin/env python3
#import os
import database
import json
import requests
import re
import requests

# api: 142.93.109.128:9876
key = "2MdW6E3dEXKasutaskRhmDhW99XP5bAWKewk9EMPZFG7T"

def run(serverlist):
    serverlist = re.sub("( ?\([^)]*\))", "", serverlist)  # delete all parentheses and their content
    serverlist = serverlist.lower()
    serverlist = serverlist.split(" ")
    for serv in serverlist:
        if "/" in serv:
            requestlist = serv.split('/')
            requestdata = {"Server": requestlist[0], "Version": requestlist[1], "APIKey": key}
            requestdata_json = json.dumps(requestdata)
            response = requests.get("http://142.93.109.128:9876/search/", data=requestdata_json)
            cvelist = response.json()
            for entry in cvelist["CVE"]:
                    cvedata = {"CVE": entry, "APIKey": key}
                    cvedata_json = json.dumps(cvedata)
                    cveresponse = requests.get("http://142.93.109.128:9876/cve/", data=cvedata_json)
                    cveresponse_json = cveresponse.json()
                    database.insert_server_vulnerability(entry, float(cveresponse_json["CVSS"]), cveresponse_json["Summary"])
                    database.insert_serversoftware_server_vulnerabilities(entry, serv)
    return


def run():
    softwarelist = database.fetch_serversoftwares()
    for software in softwarelist:
        run(software)
    return


