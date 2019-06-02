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


def run(reverse=False):
    progress_total = database.count_rows('javascripts')
    db, cursor = database.get_mysql_db_cursor()
    if reverse:
        stmt = "SELECT * " \
               "FROM " + database.database + ".javascripts " \
               "WHERE javascript_hash NOT IN " \
               "(SELECT javascript_hash " \
               "FROM aau.javascript_analyzes " \
               "WHERE analytic_tool = 'retirejs') "
    else:
        stmt = "SELECT * FROM " + database.database + ".javascripts " \
               "WHERE javascript_hash NOT IN " \
               "(SELECT javascript_hash " \
               "FROM " + database.database + ".javascript_analyzes " \
               "WHERE analytic_tool = 'retirejs')"
    cursor.execute(stmt)
    row = cursor.fetchone()

    progress_bar = ProgressBar(progress_total, bar_length=100)
    progress_bar.start()
    progress_point = 0

    try:
        os.mkdir('/tmp/knas')
    except OSError:
        pass
    while row is not None:
        progress_point += 1
        progress_bar.update(progress_point)
        with open("/tmp/knas/tmp.js", 'w+') as f:
            f.write(row[1])
            database.javascript_analyzes_retire(row[0])
        subprocess_response = subprocess.run(["retire",
                                              "--verbose",
                                              "--outputformat",
                                              "json",
                                              "--jspath",
                                              "/tmp/knas/"
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
    try:
        os.remove('/tmp/knas/tmp.js')
    except OSError:
        pass
    try:
        os.rmdir('/tmp/knas')
    except OSError:
        pass
    cursor.close()
    db.close()
