#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import mysql.connector
import subprocess
import json
import sha3


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


count_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
fetch_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
insert_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")

insert_cursor = insert_db.cursor()
count_cursor = count_db.cursor()
fetch_cursor = fetch_db.cursor()

count_cursor.execute("SELECT COUNT(*) FROM aau.javascripts")
amount_of_js = count_cursor.fetchall()[0][0]
count_cursor.close()
count_db.close()


def insert_vulnerability(id_vulnerability, vulnerability_description, vulnerability_severity):
    sql = """REPLACE INTO aau.vulnerabilities (vulnerability_id, vulnerability, severity) VALUES (%s, %s, %s)"""
    sql_params = (id_vulnerability, vulnerability_description, vulnerability_severity)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_library(id_library, library_name, library_version):
    sql = """REPLACE INTO aau.libraries (library_id, libname, version) VALUES (%s, %s, %s)"""
    sql_params = (id_library, library_name, library_version)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_vulnerability_js_relation(id_library, id_vulnerability):
    sql = """REPLACE INTO aau.libraryvulnerabilities (library_id, vulnerability_id) VALUES (%s, %s)"""
    sql_params = (id_library, id_vulnerability)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_js_library_relation(vulnerable_js_url, id_library):
    sql = """REPLACE INTO aau.javascriptlibraries (js_url, library_id) VALUES (%s, %s)"""
    sql_params = (vulnerable_js_url, id_library)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


fetch_cursor.execute("SELECT * FROM aau.javascripts ORDER BY RAND()")
row = fetch_cursor.fetchone()

progress_bar = ProgressBar(amount_of_js, bar_length=100)
progress_bar.start()
progress_point = 0

while row is not None:
    progress_point += 1
    progress_bar.update(progress_point)
    with open("js_tmp/tmp.js", 'w+') as f:
        f.write(row[0])
    subprocess_response = subprocess.run(["retire",
                                          "--verbose",
                                          "--outputformat",
                                          "json",
                                          "--jspath",
                                          "js_tmp/"
                                          ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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

                        insert_vulnerability(vulnerability_id, str(vulnerability), severity(vulnerability["severity"]))
                        insert_library(library_id, library, version)
                        insert_vulnerability_js_relation(library_id, vulnerability_id)
                        insert_js_library_relation(row[1], library_id)
    else:
        real_string = str(subprocess_response.stdout.decode("utf-8"))
        javascript_data = json.loads(real_string)

        for data in javascript_data["data"]:
            for results in data['results']:
                library = results["component"]
                version = results["version"]
                library_id = sha3.sha3_224(str(library + version).encode('utf-8')).hexdigest()

                insert_library(library_id, library, version)
                insert_js_library_relation(row[1], library_id)

    row = fetch_cursor.fetchone()

progress_bar.finished()
