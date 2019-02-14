#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import mysql.connector
import subprocess
import json
import sha3


def severity(serstr):
    if serstr == "none":
        return 0
    if serstr == "low":
        return 1
    if serstr == "medium":
        return 2
    if serstr == "high":
        return 3
    if serstr == "critical":
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
mycursor.execute("SELECT * FROM aau.javascripts")
row = mycursor.fetchone()


PB.start()
stats = 0
while row is not None:
    stats = stats + 1
    PB.update(stats)
    with open("js_tmp/tmp.js", 'w+') as f:
        f.write(row[0])
    std_out = subprocess.run(["retire", "--outputformat", "json", "--jspath", "js_tmp/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if std_out.returncode != 0:
        if std_out.returncode == 13:
            jsstr = str(std_out.stderr.decode("utf-8"))
            jsonjs = json.loads(jsstr)

            for data in jsonjs["data"]:
                for results in data['results']:
                    for vulnerability in results["vulnerabilities"]:
                        if "identifiers" in vulnerability:
                            if "CVE" in vulnerability["identifiers"]:
                                vulnerability_id = vulnerability["identifiers"]["CVE"][0]
                        else:
                            vulnerability_id = sha3.sha3_224(str(vulnerability).encode('utf-8')).hexdigest()

                        insertSQL = """REPLACE INTO aau.vulnerabilities (vulnerability_id, vulnerability, severity) VALUES (%s, %s, %s)"""
                        insert_tuple = (vulnerability_id, str(vulnerability), severity(vulnerability["severity"]))
                        insertDBCursor.execute(insertSQL, insert_tuple)

                        linkSQL = """REPLACE INTO aau.javascriptvulnerabilities (vulnerability_id, js_url) VALUES (%s, %s)"""
                        link_tuple = (vulnerability_id, row[1])
                        insertDBCursor.execute(linkSQL, link_tuple)

                        insertDB.commit()

    row = mycursor.fetchone()

PB.finished()
