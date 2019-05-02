#!/usr/bin/env python3

import database
import subprocess
import json
import sha3


def make_vulnerability_id(vulnerability):
    vulnerability_id = ''
    if "references" in vulnerability:
        if "cve" in vulnerability['references']:
            vulnerability_id = 'CVE-' + vulnerability['references']['cve'][0]

    if vulnerability_id == '':
        vulnerability_id = sha3.sha3_224(str(vulnerability).encode('utf-8')).hexdigest()

    return vulnerability_id


def run():
    sites_to_scan = database.fetch_wordpress_sites()
    for site in sites_to_scan:
        subprocess_response = subprocess.run(["wpscan",
                                              "--url",
                                              site[1].strip(),
                                              "--format", "json",
                                              "--detection-mode", "passive",
                                              "--no-banner",
                                              "--random-user-agent",
                                              "--plugins-version-detection", "passive",
                                              "--ignore-main-redirect"
                                              ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        real_str = subprocess_response.stdout.decode("utf-8")
        data = json.loads(real_str)
        if "scan_aborted" not in data:
            try:
                if "main_theme" in data:
                    if "vulnerabilities" in data['main_theme']:
                        for vulnerability in data['main_theme']['vulnerabilities']:
                            vulnerability_id = make_vulnerability_id(vulnerability)
                            if isinstance(vulnerability_id, str):
                                database.insert_cms_vulnerability(vulnerability_id, vulnerability)
                                database.insert_domain_cms_vulnerability(site[0], vulnerability_id)
            except:
                print('error')
            if "plugins" in data:
                try:
                    for plugin in data['plugins']:
                        for vulnerability in data['plugins'][plugin]['vulnerabilities']:
                            vulnerability_id = make_vulnerability_id(vulnerability)
                            if isinstance(vulnerability_id, str):
                                database.insert_cms_vulnerability(vulnerability_id, vulnerability)
                                database.insert_domain_cms_vulnerability(site[0], vulnerability_id)
                except:
                    print("error")
