#!/usr/bin/env python3

import database


def get_all_cms_vulns():
    db, cursor = database.get_mysql_db_cursor()
    sql = "SELECT * FROM aau_sample.domain_has_cms_vulnerabilities WHERE vulnerability_id LIKE 'CVE-%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def get_all_js_vulns():
    db, cursor = database.get_mysql_db_cursor()
    sql = "SELECT * FROM aau_sample.library_vulnerabilities_for_domain_id WHERE vulnerability_id LIKE 'CVE-%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def get_all_server_vulns():
    db, cursor = database.get_mysql_db_cursor()
    sql = "SELECT * FROM aau_sample.server_software_has_server_vulnerabilities"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def sites_with_js():
    db, cursor = database.get_mysql_db_cursor()
    sql = "SELECT DISTINCT domain_id FROM aau_sample.domain_has_javascripts"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def get_all_domain_ids():
    db, cursor = database.get_mysql_db_cursor()
    sql = "SELECT domain_id FROM aau_sample.domains"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def counting():
    have_at_least_one_vulnerability = 0
    have_at_least_one_old_vulnerability = 0
    uses_js = 0
    vulns_total = 0
    vulns_old_total = 0

    cms_vulns = get_all_cms_vulns()
    js_vulns = get_all_js_vulns()
    server_vulns = get_all_server_vulns()
    domains_with_js = sites_with_js()

    sites = get_all_domain_ids()
    for site in sites:
        domain_id = site[0]
        site_has_one = False
        site_has_old = False
        has_js = False
        for vuln in cms_vulns:
            if vuln[0] == domain_id:
                site_has_one = True
                vulns_total += 1
                if int(vuln[1][4:8]) <= 2018:
                    site_has_old = True
                    vulns_old_total += 1
        for vuln in js_vulns:
            if vuln[0] == domain_id:
                site_has_one = True
                vulns_total += 1
                if int(vuln[1][4:8]) <= 2018:
                    site_has_old = True
                    vulns_old_total += 1
        for vuln in server_vulns:
            if vuln[0] == domain_id:
                site_has_one = True
                vulns_total += 1
                if int(vuln[1][3:7]) <= 2018:
                    site_has_old = True
                    vulns_old_total += 1
        for js in domains_with_js:
            if js[0] == domain_id:
                has_js = True

        if site_has_one:
            have_at_least_one_vulnerability += 1
        if site_has_old:
            have_at_least_one_old_vulnerability += 1
        if has_js:
            uses_js += 1

    print("At least one: " + str(have_at_least_one_vulnerability))
    print("At least one old: " + str(have_at_least_one_old_vulnerability))
    print("Actually uses js: " + str(uses_js))
    print("Total amount of vulnerabilities: " + str(vulns_total))
    print("Total amount of old vulnerabilities: " + str(vulns_old_total))
    print("Total amount of domains: " + str(len(sites)))


counting()
