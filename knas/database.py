#!/usr/bin/env python3

import mysql.connector
import sha3
import socket
from configurations import configuration_parser

host = configuration_parser("HOST")
user = configuration_parser("USER")
password = configuration_parser("PASSWORD")
database = configuration_parser("DATABASENAME")

worker = socket.gethostname()


def get_mysql_db_cursor():
    db = mysql.connector.connect(host=host, user=user, passwd=password)
    return db, db.cursor()


def do_and_done(query, params):
    db, cursor = get_mysql_db_cursor()
    cursor.execute(query, params)
    db.commit()
    cursor.close()
    db.close()


def insert_vulnerability(id_vulnerability, vulnerability_description, vulnerability_severity):
    stmt = "INSERT IGNORE INTO " + database + ".javascript_vulnerabilities " \
          "(vulnerability_id, vulnerability_description, severity, created_at) " \
          "VALUES (%s, %s, %s, NOW())"
    params = (id_vulnerability, vulnerability_description, vulnerability_severity)
    do_and_done(stmt, params)


def javascript_analyzes_retire(js_hash):
    stmt = "INSERT IGNORE INTO " + database + ".javascript_analyzes " \
          "(javascript_hash, analytic_tool, worker, created_at) " \
          "VALUES (%s, 'retirejs', %s, NOW())"
    params = (js_hash, worker)
    do_and_done(stmt, params)


def insert_library(id_library, library_name, library_version):
    stmt = "INSERT IGNORE INTO " + database + ".libraries " \
          "(library_id, library_name, library_version, created_at) " \
          "VALUES (%s, %s, %s, NOW())"
    sql_params = (id_library, library_name, library_version)
    do_and_done(stmt, sql_params)


def insert_vulnerability_js_relation(id_library, id_vulnerability):
    stmt = "INSERT IGNORE INTO " + database + ".library_has_vulnerabilities " \
          "(library_id, vulnerability_id, created_at) " \
          "VALUES (%s, %s, NOW())"
    sql_params = (id_library, id_vulnerability)
    do_and_done(stmt, sql_params)


def insert_js_library_relation(vulnerable_js_hash, id_library):
    stmt = "INSERT IGNORE INTO " + database + ".javascript_is_library " \
          "(javascript_hash, library_id, created_at) " \
          "VALUES (%s, %s, NOW())"
    sql_params = (vulnerable_js_hash, id_library)
    do_and_done(stmt, sql_params)


def insert_cms(domain_id, cms_system):
    stmt = "INSERT IGNORE INTO " + database + ".identified_cms " \
          "(domain_id, cms_system, created_at) " \
          "VALUES (%s, %s, NOW())"
    params = (domain_id, cms_system)
    do_and_done(stmt, params)


def insert_server(domain_id, server):
    stmt = "INSERT IGNORE INTO " + database + ".server_software " \
          "(domain_id, software, created_at) " \
          "VALUES (%s, %s, NOW())"
    params = (domain_id, server)
    do_and_done(stmt, params)


def insert_x_powered_by(domain_id, x_powered_by):
    stmt = "INSERT IGNORE INTO " + database + ".powered_by " \
          "(domain_id, x_powered_by, created_at) " \
          "VALUES (%s, %s, NOW())"
    params = (domain_id, x_powered_by)
    do_and_done(stmt, params)


def insert_hsts(domain_id, policy):
    stmt = "INSERT IGNORE INTO " + database + ".hsts_policies " \
          "(domain_id, policy, created_at) " \
          "VALUES (%s, %s, NOW())"
    params = (domain_id, policy)
    do_and_done(stmt, params)


def fetch_domains(hostname):
    db, cursor = get_mysql_db_cursor()
    stmt = "SELECT domain_id, domain" \
           "FROM " + database + ".domains " \
           "WHERE domain_id IN " \
           "(SELECT domain_id " \
           "FROM aau.locked_ssl_scan " \
           "WHERE worker LIKE %s)"
    params = (hostname,)
    cursor.execute(stmt, params)
    domains = cursor.fetchall()
    cursor.close()
    db.close()

    return domains


def fetch_wordpress_sites():
    db, cursor = get_mysql_db_cursor()
    stmt = "SELECT domain_id, domain " \
           "FROM " + database + ".domains " \
           "WHERE domain_id IN " \
           "(SELECT domain_id " \
           "FROM aau.identified_cms " \
           "WHERE cms_system LIKE 'wordpress')"
    cursor.execute(stmt)
    domains = cursor.fetchall()
    cursor.close()
    db.close()
    return domains


def insert_cms_vulnerability(vulnerability_id, description):
    stmt = "INSERT IGNORE INTO " + database + ".cms_vulnerabilities " \
           "(vulnerability_id, description, created_at) " \
           "VALUES (%s, %s, NOW())"
    params = (vulnerability_id, description)
    do_and_done(stmt, params)


def insert_domain_cms_vulnerability(domain_id, vulnerability_id):
    stmt = "INSERT IGNORE INTO " + database + ".domain_has_cms_vulnerabilities (domain_id, vulnerability_id, created_at) VALUES (%s, %s, NOW())"
    params = (domain_id, vulnerability_id)
    do_and_done(stmt, params)


def ssl_lock_domains(amount, work):
    stmt = "INSERT IGNORE INTO " + database + ".locked_ssl_scan " \
           "(domain_id, worker, created_at) " \
           "SELECT domains.domain_id, %s AS 'worker', NOW() " \
           "FROM " + database + ".domains WHERE domain_id NOT IN " \
           "(SELECT domain_id FROM " + database + ".locked_ssl_scan) " \
           "AND domain_id NOT IN " \
           "(SELECT domain_id " \
           "FROM " + database + ".ssl_properties) " \
           "AND domain_id NOT IN " \
           "(SELECT domain_id " \
           "FROM " + database + ".ssl_scan_history) " \
           "ORDER BY RAND() LIMIT %s;"
    params = (work, amount)
    do_and_done(stmt, params)


def ssl_domain_log(domain_id, hostname):
    stmt = "INSERT INTO " + database + ".ssl_scan_history " \
           "(worker, domain_id, created_at) " \
           "VALUES (%s, %s, NOW());"
    params = (hostname, domain_id)
    do_and_done(stmt, params)


def ssl_unlock_domains(hostname):
    stmt = "DELETE FROM " + database + ".locked_ssl_scan " \
           "WHERE worker LIKE %s"
    params = (hostname,)
    do_and_done(stmt, params)


def ssl_save_data(ssl_cert):
    stmt = "INSERT INTO " + database + ".ssl_properties " \
           "(domain_id, " \
           "protocols, " \
           "elliptic_curves, " \
           "keysize, " \
           "has_heartbleed, " \
           "has_ticketbleed, " \
           "has_robot, " \
           "has_sec_ren, " \
           "has_sec_ci_ren, " \
           "has_crime_tls, " \
           "has_breach, " \
           "has_poodle_ssl, " \
           "has_sweet32, " \
           "has_freak, " \
           "has_drown, " \
           "has_logjam, " \
           "has_beast, " \
           "has_lucky13, " \
           "has_rc4) " \
           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    params = (
        ssl_cert.domain_id,
        ssl_cert.protocols,
        ssl_cert.ellipsis_curves,
        ssl_cert.key_size,
        ssl_cert.has_heartbleed,
        ssl_cert.has_ticketbleed,
        ssl_cert.has_ROBOT,
        ssl_cert.has_secure_renego,
        ssl_cert.has_secure_client_renego,
        ssl_cert.has_CRIME_TLS,
        ssl_cert.has_BREACH,
        ssl_cert.has_POODLE_SSL,
        ssl_cert.has_SWEET32,
        ssl_cert.has_FREAK,
        ssl_cert.has_DROWN,
        ssl_cert.has_LOGJAM,
        ssl_cert.has_BEAST,
        ssl_cert.has_LUCKY13,
        ssl_cert.has_RC4,
    )
    do_and_done(stmt, params)


def count_rows(table, is_external=False):
    db, cursor = get_mysql_db_cursor()
    if is_external:
        stmt = "SELECT COUNT(*) " \
              "FROM " + database + ".domain_has_javascripts " \
              "WHERE is_external = 1"
    else:
        stmt = "SELECT COUNT(*) FROM " + database + "." + table
    cursor.execute(stmt)
    number = cursor.fetchall()[0][0]
    cursor.close()
    db.close()
    return number


def insert_server_software(domain_id, software, version):
    software_hash = sha3.sha3_224(str(software + version).encode('utf-8')).hexdigest()
    stmt = "INSERT IGNORE INTO " + database + ".server_software " \
           "(software_hash, domain_id, software, version, created_at) " \
           "VALUES (%s, %s, %s, %s, NOW())"
    params = (software_hash, domain_id, software, version)
    do_and_done(stmt, params)


def insert_server_vulnerability(cve, score, description):
    stmt = "INSERT IGNORE INTO " + database + ".server_vulnerabilities " \
           "(cve, score, cve_description, created_at) " \
           "VALUES (%s, %s, %s, NOW())"
    params = (cve, score, description)
    do_and_done(stmt, params)


def done_tag_cms(javascript_hash):
    stmt = "INSERT IGNORE INTO " + database + ".tag_cms_history " \
           "(javascript_hash, worker, created_at) " \
           "VALUES (%s, %s, NOW())"
    params = (javascript_hash, worker)
    do_and_done(stmt, params)


def done_tag_from_header(domain_id):
    stmt = "INSERT IGNORE INTO " + database + ".generic_history " \
           "(domain_id, worker, created_at) " \
           "VALUES (%s, %s, NOW())"
    params = (domain_id, worker)
    do_and_done(stmt, params)


def insert_server_has_server_vulnerability(cve, software, version):
    software_hash = sha3.sha3_224(str(software + version).encode('utf-8')).hexdigest()
    stmt = "INSERT IGNORE INTO " + database + ".server_software_has_server_vulnerabilities " \
           "(cve, software_hash) " \
           "VALUES (%s, %s)"
    params = (cve, software_hash)
    do_and_done(stmt, params)


def fetch_server_software():
    db, cursor = get_mysql_db_cursor()
    stmt = "SELECT software, version " \
           "FROM " + database + ".server_software"
    cursor.execute(stmt)
    server_software = cursor.fetchall()
    cursor.close()
    db.close()
    return server_software
