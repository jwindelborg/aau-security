#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import subprocess
import json
import sha3
import os
import database


def severity(severity_str):
    if severity_str == "none":
        return 0
    if severity_str == "low":
        return 1
    if severity_str == "medium":
        return 2
    if severity_str == "high":
        return 3
    if severity_str == "critical":
        return 4


def run():
    progress_total = database.count_rows('javascripts')
    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT * FROM aau.javascripts ORDER BY RAND()")
    row = cursor.fetchone()

    progress_bar = ProgressBar(progress_total, bar_length=100)
    progress_bar.start()
    progress_point = 0

    while row is not None:
        progress_point += 1
        progress_bar.update(progress_point)
        with open("js_tmp/tmp.js", 'w+') as f:
            f.write(row[1])
        subprocess_response = subprocess.run(["retire",
                                              "--verbose",
                                              "--outputformat",
                                              "json",
                                              "--jspath",
                                              "js_tmp/"
                                              ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            if subprocess_response.returncode != 0:
                if subprocess_response.returncode == 13:
                    real_string = str(subprocess_response.stderr.decode("utf-8"))
                    javascript_data = json.loads(real_string)

                    for data in javascript_data["data"]:
                        for results in data['results']:
                            for vulnerability in results["vulnerabilities"]:
                                if "identifiers" in vulnerability and "CVE" in vulnerability["identifiers"]:
                                    vulnerability_id = vulnerability["identifiers"]["CVE"][0]
                                else:
                                    vulnerability_id = sha3.sha3_224(str(vulnerability).encode('utf-8')).hexdigest()

                                library = results["component"]
                                version = results["version"]
                                library_id = sha3.sha3_224(str(library + version).encode('utf-8')).hexdigest()

                                database.insert_vulnerability(vulnerability_id, str(vulnerability),
                                                              severity(vulnerability["severity"]))
                                database.insert_library(library_id, library, version)
                                database.insert_vulnerability_js_relation(library_id, vulnerability_id)
                                database.insert_js_library_relation(row[0], library_id)
            else:
                real_string = str(subprocess_response.stdout.decode("utf-8"))
                javascript_data = json.loads(real_string)

                for data in javascript_data["data"]:
                    for results in data['results']:
                        library = results["component"]
                        version = results["version"]
                        library_id = sha3.sha3_224(str(library + version).encode('utf-8')).hexdigest()

                        database.insert_library(library_id, library, version)
                        database.insert_js_library_relation(row[0], library_id)
        except:
            print("Could not handle " + row[0])

        row = cursor.fetchone()
    os.remove('js_tmp/tmp.js')
    os.rmdir('js_tmp')
    cursor.close()
    db.close()
