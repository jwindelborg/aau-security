#!/usr/bin/env python3
import database
import json
import re
import requests
from ezprogress.progressbar import ProgressBar

# api: 142.93.109.128:9876
key = "2MdW6E3dEXKasutaskRhmDhW99XP5bAWKewk9EMPZFG7T"


def run_list(server_raw):
    server_list = re.sub("( ?\([^)]*\))", "", server_raw[1])  # delete all parentheses and their content
    server_list = server_list.lower()
    server_list = server_list.split(" ")

    for server in server_list:
        if server is "":
            continue
        if "/" in server:
            request_list = server.split('/')
            request_list[0] = request_list[0].replace("-", ":").replace("+", " ")  # cve-search uses : instead of -. some sites write their server software list with + instead of space-separating
            if len(request_list) is not 2 or request_list[1] is "":
                database.insert_server_software(server_raw[0], request_list[0], "")
                continue
            request_data = {"Server": request_list[0], "Version": request_list[1], "APIKey": key}
            request_data_json = json.dumps(request_data)

            try:
                response = requests.get("http://142.93.109.128:9876/search/", data=request_data_json)
                cve_list = response.json()
            except:
                print("Illegal chars in string")
                continue
            if cve_list["CVE"] is None:
                continue
            for entry in cve_list["CVE"]:
                cve_data = {"CVE": entry, "APIKey": key}
                cve_data_json = json.dumps(cve_data)
                cve_response = requests.get("http://142.93.109.128:9876/cve/", data=cve_data_json)
                cve_response_json = cve_response.json()
                database.insert_server_vulnerability(entry, float(cve_response_json["CVSS"]),
                                                     cve_response_json["Summary"])
                database.insert_server_has_server_vulnerability(entry, request_list[0], request_list[1])
            database.insert_server_software(server_raw[0], request_list[0], request_list[1])

        else:
            database.insert_server_software(server_raw[0], server, "")


def run():
    software_list = database.fetch_server_softwares_raw()
    number_of_uniques = len(software_list)
    progress_bar = ProgressBar(number_of_uniques, bar_length=100)
    progress_bar.start()
    progress_point = 0

    for software in software_list:
        progress_point += 1
        progress_bar.update(progress_point)
        run_list(software)
