#!/usr/bin/env python3

import socket
import subprocess
from pathlib import Path
import os
import threading
import database

hostname = socket.gethostname()
home = str(Path.home())

finished = False


class SSLCertificate:
    domain_id = 0
    protocols = ""
    ellipsis_curves = ""
    key_size = ""
    has_heartbleed = False
    has_ticketbleed = False
    has_ROBOT = False
    has_secure_renego = False
    has_secure_client_renego = False
    has_CRIME_TLS = False
    has_BREACH = False
    has_POODLE_SSL = False
    has_SWEET32 = False
    has_FREAK = False
    has_DROWN = False
    has_LOGJAM = False
    has_BEAST = False
    has_LUCKY13 = False
    has_RC4 = False


def has_protocol(file, protocol):
    for line in file:
        if line.startswith("\"" + protocol + "\""):
            if "\"offered\"" in line:
                return True
    return False


def get_key_size(file):
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


def protocols_str(file):
    search_protocols = ["SSLv2", "SSLv3", "TLS1", "TLS1_2", "TLS1_3"]
    protocols = ""
    for protocol in search_protocols:
        if has_protocol(file, protocol):
            protocols += protocol
    return protocols


def build_ssl_cert(file, domain_id):
    data = SSLCertificate()
    data.domain_id = domain_id
    data.protocols = protocols_str(file)
    data.key_size = get_key_size(file)
    data.has_heartbleed = has_vulnerability(file, "heartbleed")
    data.has_ticketbleed = has_vulnerability(file, "ticketbleed")
    data.has_ROBOT = has_vulnerability(file, "ROBOT")
    data.has_secure_renego = has_vulnerability(file, "secure_renego")
    data.has_secure_client_renego = has_vulnerability(file, "secure_client_renego")
    data.has_CRIME_TLS = has_vulnerability(file, "CRIME_TLS")
    data.has_BREACH = has_vulnerability(file, "BREACH")
    data.has_POODLE_SSL = has_vulnerability(file, "POODLE_SSL")
    data.has_SWEET32 = has_vulnerability(file, "SWEET32")
    data.has_FREAK = has_vulnerability(file, "FREAK")
    data.has_DROWN = has_vulnerability(file, "DROWN")
    data.has_LOGJAM = has_vulnerability(file, "LOGJAM")
    data.has_BEAST = has_vulnerability(file, "BEAST")
    data.has_LUCKY13 = has_vulnerability(file, "LUCKY13")
    data.has_RC4 = has_vulnerability(file, "RC4")

    return data


def process_a_domain(domain):
    print(domain[1])
    if os.path.exists(str(os.path.dirname(__file__)) + domain[1].rstrip()):
        os.remove(str(os.path.dirname(__file__)) + domain[1].rstrip())
    subprocess_response = subprocess.run([home + "/testssl.sh/testssl.sh", "--fast", "--warnings", "batch", "--csv", "--csvfile",
                                          domain[1].rstrip(), domain[1].rstrip()],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if subprocess_response.stderr:
        print("Skip: " + domain[1])
    else:
        with open(domain[1].rstrip()) as f:
            database.ssl_save_data(build_ssl_cert(f.readlines(), domain[0]))
    if os.path.exists(str(os.path.dirname(__file__)) + domain[1].rstrip()):
        os.remove(str(os.path.dirname(__file__)) + domain[1].rstrip())
    database.ssl_domain_log(domain[0], hostname)


def process_batch(threads_desired, domains_to_reserve):
    global finished
    database.ssl_unlock_domains(hostname)
    database.ssl_lock_domains(domains_to_reserve, hostname)
    domains = database.fetch_domains(hostname)

    if len(domains) < 1:
        finished = True
        return

    while len(domains) >= 1:
        if threading.active_count()-1 < threads_desired:
            threading.Thread(target=process_a_domain, args=(domains.pop(0),),).start()

    database.ssl_unlock_domains(hostname)


def run(threads=7, domains_to_reserve=100):
    global finished
    while not finished:
        process_batch(threads, domains_to_reserve)

