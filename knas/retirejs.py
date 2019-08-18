#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import subprocess
import json
import sha3
import os
import database
import time
import threading

total = 0
threads_desired = 20


def tell_me_progress(total_amount):
    global total
    progress_bar = ProgressBar(total_amount, bar_length=100)
    progress_bar.start()
    while True:
        progress_bar.update(total)
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
    stmt = "SELECT javascript_hash FROM aau.javascripts WHERE javascript_hash NOT IN (SELECT javascript_hash FROM aau.javascript_analyzes WHERE analytic_tool = 'retirejs') ORDER BY javascript_hash DESC"
    cursor.execute(stmt)
    rows = cursor.fetchall()
    cursor.close()
    db.close()
    return rows


def run():
    global threads_desired
    files = fetch_queue()
    total_amount = len(files)
    threading.Thread(target=tell_me_progress, args=(total_amount, ), ).start()
    start_at = 0
    end_at = 10000
    increment_size = 10000
    pls_stop = False
    list_to_process = list(files)
    run_an_instance(list_to_process)
    sys.exit(0)
    while not pls_stop:
        if end_at >= total_amount:
            pls_stop = True
        if threading.active_count()-1 < threads_desired:
            list_to_process = list(files[start_at:end_at])
            threading.Thread(target=run_an_instance, args=(list_to_process, )).start()
            start_at = end_at
            end_at = end_at + increment_size
            if end_at > total_amount:
                end_at = total_amount


def run_an_instance(scripts_to_process):
    global total
    for thesum in scripts_to_process:
        thesum = thesum[0]
        total += 1
        db, cursor = database.get_mysql_db_cursor()
        stmt = "SELECT javascript_hash, script FROM aau.javascripts WHERE javascript_hash = %s"
        params = (thesum,)
        cursor.execute(stmt, params)
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        for row in rows:
            try:
                os.mkdir('/tmp/' + thesum)
            except OSError:
                pass
            with open("/tmp/" + thesum + "/tmp.js", 'w+') as f:
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
                pass
                # TODO: Dump to log file
                # print("Could not handle " + row[0])
            try:
                os.remove('/tmp/' + thesum + '/tmp.js')
            except OSError:
                pass
            try:
                os.rmdir('/tmp/' + thesum)
            except OSError:
                pass


run()
