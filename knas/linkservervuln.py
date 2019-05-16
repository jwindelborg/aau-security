#!/usr/bin/env python3
import database
import json
import re
import requests
from ezprogress.progressbar import ProgressBar

# api: 142.93.109.128:9876
key = "2MdW6E3dEXKasutaskRhmDhW99XP5bAWKewk9EMPZFG7T"


def make_server_software(domain_id, raw):
    server_list = re.sub(r"( ?\([^)]*\))", "", raw)  # delete all parentheses and their content
    server_list = server_list.lower().replace("+", " ").replace(";", " ").split(" ")
    for server in server_list:
        if server is "":
            continue
        if "/" in server:
            request_list = server.split('/')
            request_list[0] = request_list[0].replace("-", ":")  # cve-search uses : instead of -
            if len(request_list) is 2 and request_list[1] is not "":
                database.insert_server_software(domain_id, request_list[0], request_list[1])
                link_vulnerabilities(request_list[0], request_list[1])
                continue
        server = server.replace('/', '')
        database.insert_server_software(domain_id, server, "")


def link_vulnerabilities(software, version):
    request_data = {"Server": software, "Version": version, "APIKey": key}
    request_data_json = json.dumps(request_data)

    try:
        response = requests.get("http://142.93.109.128:9876/search/", data=request_data_json)
        cve_list = response.json()
    except:
        print("Illegal chars in string")
        return
    if cve_list["CVE"] is None:
        return
    for entry in cve_list["CVE"]:
        cve_data = {"CVE": entry, "APIKey": key}
        cve_data_json = json.dumps(cve_data)
        cve_response = requests.get("http://142.93.109.128:9876/cve/", data=cve_data_json)
        cve_response_json = cve_response.json()
        database.insert_server_vulnerability(entry, float(cve_response_json["CVSS"]),
                                             cve_response_json["Summary"])
        database.insert_server_has_server_vulnerability(entry, software, version)


def run():
    software_list = database.fetch_server_software()
    number_of_uniques = len(software_list)
    progress_bar = ProgressBar(number_of_uniques, bar_length=100)
    progress_bar.start()
    progress_point = 0

    for entry in software_list:
        progress_point += 1
        progress_bar.update(progress_point)
        link_vulnerabilities(entry[0], entry[1])
