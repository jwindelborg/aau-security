#!/usr/bin/env python3

from configurations import configuration_parser
import threading
import database

host = configuration_parser("HOST")
user = configuration_parser("USER")
password = configuration_parser("PASSWORD")


def check_then_insert(domain):
    db, cursor = database.get_mysql_db_cursor()
    sql = """SELECT * FROM aau.domains WHERE domain LIKE %s"""
    params = (domain,)
    cursor.execute(sql, params)
    results = cursor.fetchall()
    if len(results) < 1:
        insert_domain(domain)
    cursor.close()
    db.close()


def insert_domain(domain):
    sql = """INSERT INTO aau.domains (domain) VALUE (%s)"""
    params = (domain,)
    database.do_and_done(sql, params)


def process_list(domains):
    for domain in domains:
        check_then_insert(domain.rstrip())


with open('zonefile') as f:
    threads = 9
    increment_size = 100000

    zone_file = f.readlines()
    commit_suicide = False
    start_from = 0
    end_at = increment_size
    while True:
        if threading.active_count() - 1 < threads:
            threading.Thread(target=process_list, args=(zone_file[start_from:end_at],), ).start()
            if commit_suicide:
                break
            start_from = end_at + 1
            if len(zone_file[start_from:]) >= increment_size:
                end_at += increment_size
            else:
                end_at = len(zone_file[start_from:])
                commit_suicide = True
