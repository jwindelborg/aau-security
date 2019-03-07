#!/usr/bin/env python3

import socket
import mysql.connector
import subprocess
from pathlib import Path
import os
import threading
import argparse

hostname = socket.gethostname()
home = str(Path.home())
number_of_domains = 100

running = 0
all_done = False


def arg_parser():
    parser = argparse.ArgumentParser(description="Test SSL for websites")
    parser.add_argument("threads", nargs='+', default=7, action='store', help='Number of threads to run')
    return parser.parse_args()


def has_protocol(file, protocol):
    for line in file:
        if line.startswith("\"" + protocol + "\""):
            if "\"offered\"" in line:
                return True
    return False


def get_keysize(file):
    for line in file:
        if line.startswith("\"cert_keySize"):
            data = line.split(',')
            return data[4]
    return ""


def has_vulnerability(file, vulnerability):
    for line in file:
        if line.startswith("\"" + vulnerability + "\""):
            if "not vulnerable" not in line:
                return True
    return False


def save_data(file, domain_id):
    protocols = ""
    if has_protocol(file, "SSLv2"):
        protocols += "SSLv2,"
    if has_protocol(file, "SSLv3"):
        protocols += "SSLv3,"
    if has_protocol(file, "TLS1"):
        protocols += "TLS1,"
    if has_protocol(file, "TLS1_2"):
        protocols += "TLS1_2,"
    if has_protocol(file, "TLS1_3"):
        protocols += "TLS1_3,"

    save_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
    save_cursor = save_db.cursor()
    stmt = """INSERT INTO `aau`.`domainsslscan` (
                `domain_id`, 
                `protocols`, 
                `elliptic_curves`, 
                `keysize`, 
                `has_heartbleed`, 
                `has_ticketbleed`, 
                `has_robot`, 
                `has_sec_ren`, 
                `has_sec_ci_ren`, 
                `has_crime_tls`, 
                `has_breach`, 
                `has_poodle_ssl`, 
                `has_sweet32`, 
                `has_freak`, 
                `has_drown`, 
                `has_logjam`, 
                `has_beast`, 
                `has_lucky13`, 
                `has_rc4`) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    params = (
        domain_id,
        protocols,
        "",  # TODO: Elliptic curves, not yet sure how to extract
        get_keysize(file),
        has_vulnerability(file, "heartbleed"),
        has_vulnerability(file, "ticketbleed"),
        has_vulnerability(file, "ROBOT"),
        has_vulnerability(file, "secure_renego"),
        has_vulnerability(file, "secure_client_renego"),
        has_vulnerability(file, "CRIME_TLS"),
        has_vulnerability(file, "BREACH"),
        has_vulnerability(file, "POODLE_SSL"),
        has_vulnerability(file, "SWEET32"),
        has_vulnerability(file, "FREAK"),
        has_vulnerability(file, "DROWN"),
        has_vulnerability(file, "LOGJAM"),
        has_vulnerability(file, "BEAST"),
        has_vulnerability(file, "LUCKY13"),
        has_vulnerability(file, "RC4")
    )
    save_cursor.execute(stmt, params)
    save_db.commit()
    save_db.close()


def lock_domains():
    lock_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
    lock_cursor = lock_db.cursor()
    lock_stmt = """INSERT IGNORE INTO aau.ssllock (domain_id, worker, locked_at)
                    SELECT domains.domain_id, %s AS 'worker', NOW()
                    FROM aau.domains
                    WHERE domain_id NOT IN (
                      SELECT domain_id FROM aau.ssllock)
                        AND domain_id NOT IN (
                          SELECT domain_id
                          FROM aau.domainsslscan)
                    ORDER BY RAND() LIMIT %s;"""
    lock_params = (socket.gethostname(), number_of_domains)
    lock_cursor.execute(lock_stmt, lock_params)
    lock_db.commit()
    lock_db.close()


def unlock_domains():
    clear_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
    clear_cursor = clear_db.cursor()
    clear_stmt = """DELETE FROM aau.ssllock WHERE worker LIKE %s"""
    clear_params = (hostname,)
    clear_cursor.execute(clear_stmt, clear_params)
    clear_db.commit()
    clear_db.close()


def fetch_domains():
    select_db = mysql.connector.connect(host="aau.windelborg.info", user="aau", passwd="2387AXumK52aeaSA")
    select_cursor = select_db.cursor()
    select_stmt = """SELECT domain_id, domain FROM aau.domains WHERE domain_id IN (SELECT domain_id FROM aau.ssllock WHERE worker LIKE %s)"""
    select_params = (hostname,)
    select_cursor.execute(select_stmt, select_params)

    domains = select_cursor.fetchall()
    select_db.close()

    return domains


def process_a_domain(domain):
    global running
    running += 1
    print(domain[1])
    if os.path.exists(str(os.path.dirname(__file__)) + domain[1].rstrip()):
        os.remove(str(os.path.dirname(__file__)) + domain[1].rstrip())
    subprocess_response = subprocess.run([home + "/testssl.sh/testssl.sh", "--fast", "--warnings", "batch", "--csv", "--csvfile", domain[1].rstrip(), domain[1].rstrip()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if subprocess_response.stderr:
        print("Skip: " + domain[1])
    else:
        with open(domain[1].rstrip()) as f:
            save_data(f.readlines(), domain[0])
    running -= 1


def process_batch(numofthreads):
    global all_done
    unlock_domains()
    lock_domains()
    domains = fetch_domains()

    if len(domains) < 1:
        all_done = True
        return

    while len(domains) >= 1:
        if running < numofthreads:
            threading.Thread(target=process_a_domain,
                             args=(domains.pop(0),),
                             ).start()

    unlock_domains()


def main():
    args = arg_parser()
    while not all_done:
        process_batch(args.threads)


if __name__ == "__main__":
    main()

