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
    sql = """REPLACE INTO aau.vulnerabilities (vulnerability_id, vulnerability, severity, discovered) VALUES (%s, %s, %s, NOW())"""
    params = (id_vulnerability, vulnerability_description, vulnerability_severity)
    do_and_done(sql, params)


def insert_library(id_library, library_name, library_version):
    sql = """REPLACE INTO aau.libraries (library_id, libname, version, library_tagged) VALUES (%s, %s, %s, NOW())"""
    sql_params = (id_library, library_name, library_version)
    do_and_done(sql, sql_params)


def insert_vulnerability_js_relation(id_library, id_vulnerability):
    sql = """REPLACE INTO aau.libraryvulnerabilities (library_id, vulnerability_id, vulnerability_added) VALUES (%s, %s, NOW())"""
    sql_params = (id_library, id_vulnerability)
    do_and_done(sql, sql_params)


def insert_js_library_relation(vulnerable_js_hash, id_library):
    sql = """REPLACE INTO aau.javascriptlibraries (js_hash, library_id, library_identified_time) VALUES (%s, %s, NOW())"""
    sql_params = (vulnerable_js_hash, id_library)
    do_and_done(sql, sql_params)


def insert_cms(domain_id, cms_system):
    sql = """REPLACE INTO aau.identifiedcms (domain_id, cms_system, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, cms_system)
    do_and_done(sql, params)


def insert_server(domain_id, server):
    sql = """REPLACE INTO aau.serversoftware (domain_id, software, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, server)
    do_and_done(sql, params)


def insert_x_poewered_by(domain_id, x_powered_by):
    sql = """REPLACE INTO aau.poweredby (domain_id, xPoweredBy, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, x_powered_by)
    do_and_done(sql, params)


def insert_hsts(domain_id, policy):
    sql = """REPLACE INTO aau.hsts (domain_id, policy, discovered) VALUES (%s, %s, NOW())"""
    params = (domain_id, policy)
    do_and_done(sql, params)


def count_rows(table):
    db, cursor = get_mysql_db_cursor()
    sql = """SELECT COUNT(*) FROM aau.%s"""
    params = (table,)
    cursor.execute(sql, params)
    number = cursor.fetchall()[0][0]
    cursor.close()
    db.close()
    return number
