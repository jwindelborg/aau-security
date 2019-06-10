#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import subprocess
import json
import sha3
import os
import database
import time
import threading

progresses = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


def count_processes():
    global progresses
    count = 0
    for i in progresses:
        count += i
    return count


def tell_me_progress(total_amount):
    progress_bar = ProgressBar(total_amount, bar_length=100)
    progress_bar.start()
    while True:
        progress_bar.update(count_processes())
        time.sleep(0.5)


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


def fetch_queue():
    db, cursor = database.get_mysql_db_cursor()
    stmt = "SELECT javascript_hash FROM aau.javascripts WHERE javascript_hash NOT IN (SELECT javascript_hash FROM aau.javascript_analyzes WHERE analytic_tool = 'retirejs')"
    cursor.execute(stmt)
    rows = cursor.fetchall()
    cursor.close()
    db.close()
    return rows


def run():
    files = fetch_queue()

    total_amount = files.count()
    tell_me_progress(total_amount)
    start_at = 0
    end_at = 10000
    increment_size = 10000
    pls_stop = False
    while not pls_stop:
        if end_at >= total_amount:
            pls_stop = True
        if threading.active_count()-1 < 10:
            threading.Thread(target=run_an_instance, args=(files[start_at:end_at]), ).start()
            start_at = end_at
            end_at = end_at + increment_size
            if end_at > total_amount:
                end_at = total_amount


def run_an_instance(scripts_to_process):
    try:
        for thesum in scripts_to_process:
            db, cursor = database.get_mysql_db_cursor()
            stmt = "SELECT javascript_hash FROM aau.javascripts WHERE javascript_hash = %s"
            params = (thesum,)
            cursor.execute(stmt, params)
            row = cursor.fetchall()
            cursor.close()
            db.close()

            try:
                os.mkdir('/tmp/' + thesum)
            except OSError:
                pass
            while row is not None:
                with open("/tmp/"+ thesum + "/tmp.js", 'w+') as f:
                    f.write(row[1])
                    database.javascript_analyzes_retire(row[0])
                subprocess_response = subprocess.run(["retire",
                                                      "--verbose",
                                                      "--outputformat",
                                                      "json",
                                                      "--jspath",
                                                      "/tmp/" + thesum
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
            try:
                os.remove('/tmp/' + thesum + '/tmp.js')
            except OSError:
                pass
            try:
                os.rmdir('/tmp/' + thesum)
            except OSError:
                pass
    except:
        print("Horrible exception")


run()
