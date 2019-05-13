#!/usr/bin/env python3
import database
import json
import re
import requests
from ezprogress.progressbar import ProgressBar


# api: 142.93.109.128:9876
key = "2MdW6E3dEXKasutaskRhmDhW99XP5bAWKewk9EMPZFG7T"


def run_list(input):
    serverlist = input[0]
    serverlist = re.sub("( ?\([^)]*\))", "", serverlist)  # delete all parentheses and their content
    serverlist = serverlist.lower()
    serverlist = serverlist.split(" ")

    for serv in serverlist:
        print(serv)
        if "/" in serv:
            requestlist = serv.split('/')
            requestlist[0] = requestlist[0].replace("-", ":").replace("+", " ")  #cve-search uses : instead of -. some sites write their server software list with + instead of space-separating
            if len(requestlist) is not 2 or requestlist[1] is "":
                continue
            requestdata = {"Server": requestlist[0], "Version": requestlist[1], "APIKey": key}
            requestdata_json = json.dumps(requestdata)

            try:
                response = requests.get("http://142.93.109.128:9876/search/", data=requestdata_json)
                cvelist = response.json()
            except:
                print("Illegal chars in string")
                continue
            if cvelist["CVE"] is None:
                continue
            for entry in cvelist["CVE"]:
                cvedata = {"CVE": entry, "APIKey": key}
                cvedata_json = json.dumps(cvedata)
                cveresponse = requests.get("http://142.93.109.128:9876/cve/", data=cvedata_json)
                cveresponse_json = cveresponse.json()
                database.insert_server_vulnerability(entry, float(cveresponse_json["CVSS"]),
                                                     cveresponse_json["Summary"])
                database.insert_serversoftware_server_vulnerabilities(entry, serv)


def run():
    softwarelist = database.fetch_serversoftwares()
    print(softwarelist)
    number_of_uniques = len(softwarelist)
    progress_bar = ProgressBar(number_of_uniques, bar_length=100)
    progress_bar.start()
    progress_point = 0

    for software in softwarelist:
        progress_point += 1
        progress_bar.update(progress_point)
        run_list(software)
