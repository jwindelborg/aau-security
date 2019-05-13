import mysql.connector


def get_mysql_db_cursor():
    db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")
    return db, db.cursor()


def do_and_done(query, params):
    db, cursor = get_mysql_db_cursor()
    cursor.execute(query, params)
    db.commit()
    cursor.close()
    db.close()


def insert_vulnerability(id_vulnerability, vulnerability_description, vulnerability_severity):
    sql = """INSERT IGNORE INTO aau.vulnerabilities (vulnerability_id, vulnerability, severity, discovered) VALUES (%s, %s, %s, NOW())"""
    params = (id_vulnerability, vulnerability_description, vulnerability_severity)
    do_and_done(sql, params)


def insert_library(id_library, library_name, library_version):
    sql = """INSERT IGNORE INTO aau.libraries (library_id, libname, version, library_tagged) VALUES (%s, %s, %s, NOW())"""
    sql_params = (id_library, library_name, library_version)
    do_and_done(sql, sql_params)


def insert_vulnerability_js_relation(id_library, id_vulnerability):
    sql = """INSERT IGNORE INTO aau.libraryvulnerabilities (library_id, vulnerability_id, vulnerability_added) VALUES (%s, %s, NOW())"""
    sql_params = (id_library, id_vulnerability)
    do_and_done(sql, sql_params)


def insert_js_library_relation(vulnerable_js_hash, id_library):
    sql = """INSERT IGNORE INTO aau.javascriptlibraries (js_hash, library_id, library_identified_time) VALUES (%s, %s, NOW())"""
    sql_params = (vulnerable_js_hash, id_library)
    do_and_done(sql, sql_params)


def insert_cms(domain_id, cms_system):
    sql = """INSERT IGNORE INTO aau.identifiedcms (domain_id, cms_system, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, cms_system)
    do_and_done(sql, params)


def insert_server(domain_id, server):
    sql = """INSERT IGNORE INTO aau.serversoftware (domain_id, software, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, server)
    do_and_done(sql, params)


def insert_x_poewered_by(domain_id, x_powered_by):
    sql = """INSERT IGNORE INTO aau.poweredby (domain_id, xPoweredBy, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, x_powered_by)
    do_and_done(sql, params)


def insert_hsts(domain_id, policy):
    sql = """INSERT IGNORE INTO aau.hsts (domain_id, policy, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, policy)
    do_and_done(sql, params)


def fetch_domains(hostname):
    db, cursor = get_mysql_db_cursor()
    sql = """SELECT domain_id, domain FROM aau.domains WHERE domain_id IN (SELECT domain_id FROM aau.ssllock WHERE worker LIKE %s)"""
    params = (hostname,)
    cursor.execute(sql, params)
    domains = cursor.fetchall()
    cursor.close()
    db.close()

    return domains


def fetch_wordpress_sites():
    db, cursor = get_mysql_db_cursor()
    stmt = """SELECT domain_id, domain FROM aau.domains WHERE domain_id IN (SELECT domain_id FROM aau.identifiedcms WHERE cms_system LIKE 'wordpress')"""
    cursor.execute(stmt)
    domains = cursor.fetchall()
    cursor.close()
    db.close()
    return domains


def insert_cms_vulnerability(vulnerability_id, description):
    stmt = """INSERT IGNORE INTO aau.cmsvulnerability (vulnerability_id, description, date_added) VALUES (%s, %s, NOW())"""
    params = (vulnerability_id, description)
    do_and_done(stmt, params)


def insert_domain_cms_vulnerability(domain_id, vulnerability_id):
    stmt = """INSERT IGNORE INTO aau.domainscmsvulnerabilities (domain_id, vulnerability_id, vulnerability_discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, vulnerability_id)
    do_and_done(stmt, params)


def ssl_lock_domains(amount, worker):
    stmt = """INSERT IGNORE INTO aau.ssllock (domain_id, worker, locked_at)
                    SELECT domains.domain_id, %s AS 'worker', NOW()
                    FROM aau.domains
                    WHERE domain_id NOT IN (
                      SELECT domain_id FROM aau.ssllock)
                        AND domain_id NOT IN (
                          SELECT domain_id
                          FROM aau.domainsslscan)
                        AND domain_id NOT IN (
                        SELECT domain_id
                        FROM aau.sslscanhistory)
                    ORDER BY RAND() LIMIT %s;"""
    params = (worker, amount)
    do_and_done(stmt, params)


def ssl_domain_log(domain_id, hostname):
    stmt = """INSERT INTO aau.sslscanhistory (worker, domain_id, logged_at) VALUES (%s, %s, NOW());"""
    params = (hostname, domain_id)
    do_and_done(stmt, params)


def ssl_unlock_domains(hostname):
    stmt = """DELETE FROM aau.ssllock WHERE worker LIKE %s"""
    params = (hostname,)
    do_and_done(stmt, params)


def ssl_save_data(ssl_cert):
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


def count_rows(table):
    db, cursor = get_mysql_db_cursor()
    sql = "SELECT COUNT(*) FROM aau." + table
    cursor.execute(sql)
    number = cursor.fetchall()[0][0]
    cursor.close()
    db.close()
    return number


def check_vulnerability(cve, softwaretype):
    db, cursor = get_mysql_db_cursor()
    if softwaretype == "cms":
        tablename = "cmsvulnerability"
    elif softwaretype == "server":
        tablename = "servervulnerabilities"
    else:
        print("WRONG TYPE !")
        return 0
    sql = "SELECT COUNT(*) FROM aau." + tablename + "WHERE vulnerability_id LIKE " + cve
    cursor.execute(sql)
    exists = cursor.fetchall()
    cursor.close()
    db.close()
    return exists


def insert_server_vulnerability(cve, score, description):
    stmt = """INSERT IGNORE INTO aau.servervulnerabilities (cve, score, description, date_added) VALUES (%s, %s, %s, NOW())"""
    params = (cve, score, description)
    do_and_done(stmt, params)


def insert_serversoftware_server_vulnerabilities(cve, software):
    stmt = """INSERT IGNORE INTO aau.serversoftwareservervulnerabilities (cve, software) VALUES (%s, %s)"""
    params = (cve, software)
    do_and_done(stmt, params)

def fetch_serversoftwares():
    db, cursor = get_mysql_db_cursor()
    stmt = """SELECT DISTINCT software FROM aau.serversoftware"""
    cursor.execute(stmt)
    domains = cursor.fetchall()
    cursor.close()
    db.close()
    return domains
