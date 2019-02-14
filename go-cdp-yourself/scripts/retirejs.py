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


countdb = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
mydb = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
insertDB = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")

insertDBCursor = insertDB.cursor()

count_cursor = countdb.cursor()
count_cursor.execute("SELECT COUNT(*) FROM aau.javascripts")
amount_of_js = count_cursor.fetchall()[0][0]
PB = ProgressBar(amount_of_js, bar_length=100)
count_cursor.close()

mycursor = mydb.cursor()
mycursor.execute("SELECT * FROM aau.javascripts ORDER BY RAND()")
row = mycursor.fetchone()


def insert_vulnerability(vuln_id, vuln_desc, vuln_severity):
    sql = """REPLACE INTO aau.vulnerabilities (vulnerability_id, vulnerability, severity) VALUES (%s, %s, %s)"""
    sql_params = (vuln_id, vuln_desc, vuln_severity)
    insertDBCursor.execute(sql, sql_params)
    insertDB.commit()


def insert_library(lib_id, library, version):
    sql = """REPLACE INTO aau.libraries (library_id, libname, version) VALUES (%s, %s, %s)"""
    sql_params = (lib_id, library, version)
    insertDBCursor.execute(sql, sql_params)
    insertDB.commit()


def insert_vulnerability_js_relation(library_id, vulnerability_id):
    sql = """REPLACE INTO aau.libraryvulnerabilities (library_id, vulnerability_id) VALUES (%s, %s)"""
    sql_params = (library_id, vulnerability_id)
    insertDBCursor.execute(sql, sql_params)
    insertDB.commit()


def insert_js_library_relation(vulnerable_js_url, library_id):
    sql = """REPLACE INTO aau.javascriptlibraries (js_url, library_id) VALUES (%s, %s)"""
    sql_params = (vulnerable_js_url, library_id)
    insertDBCursor.execute(sql, sql_params)
    insertDB.commit()


PB.start()
stats = 0
while row is not None:
    stats = stats + 1
    PB.update(stats)
    with open("js_tmp/tmp.js", 'w+') as f:
        f.write(row[0])
    sub_res = subprocess.run(["retire",
                              "--verbose",
                              "--outputformat",
                              "json",
                              "--jspath",
                              "js_tmp/"
                              ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if sub_res.returncode != 0:
        if sub_res.returncode == 13:
            real_string = str(sub_res.stderr.decode("utf-8"))
            javascript_data = json.loads(real_string)

            for data in javascript_data["data"]:
                for results in data['results']:
                    for vulnerability in results["vulnerabilities"]:
                        if "identifiers" in vulnerability:
                            if "CVE" in vulnerability["identifiers"]:
                                vulnerability_id = vulnerability["identifiers"]["CVE"][0]
                            else:
                                vulnerability_id = sha3.sha3_224(str(vulnerability).encode('utf-8')).hexdigest()
                        else:
                            vulnerability_id = sha3.sha3_224(str(vulnerability).encode('utf-8')).hexdigest()

                        library = results["component"]
                        version = results["version"]
                        lib_id = sha3.sha3_224(str(library + version).encode('utf-8')).hexdigest()

                        insert_vulnerability(vulnerability_id, str(vulnerability), severity(vulnerability["severity"]))
                        insert_library(lib_id, library, version)
                        insert_vulnerability_js_relation(lib_id, vulnerability_id)
                        insert_js_library_relation(row[1], lib_id)
    else:
        real_string = str(sub_res.stdout.decode("utf-8"))
        javascript_data = json.loads(real_string)

        for data in javascript_data["data"]:
            for results in data['results']:
                library = results["component"]
                version = results["version"]
                lib_id = sha3.sha3_224(str(library + version).encode('utf-8')).hexdigest()

                insert_library(lib_id, library, version)
                insert_js_library_relation(row[1], lib_id)

    row = mycursor.fetchone()

PB.finished()
