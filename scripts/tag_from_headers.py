#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import mysql.connector

count_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")
fetch_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")
insert_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")

insert_cursor = insert_db.cursor()
count_cursor = count_db.cursor()
fetch_cursor = fetch_db.cursor()


count_cursor.execute("SELECT COUNT(*) FROM aau.httpheaders")
number_of_headers = count_cursor.fetchall()[0][0]
count_cursor.close()
count_db.close()


def insert_server(domain_id, server):
    sql = """REPLACE INTO aau.serversoftware (domain_id, software, discovered) VALUES (%s, %s, NOW())"""
    sql_params = (domain_id, server)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_x_poewered_by(domain_id, x_powered_by):
    sql = """REPLACE INTO aau.poweredby (domain_id, xPoweredBy, discovered) VALUES (%s, %s, NOW())"""
    sql_params = (domain_id, x_powered_by)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_hsts(domain_id, policy):
    sql = """REPLACE INTO aau.hsts (domain_id, policy, discovered) VALUES (%s, %s, NOW())"""
    sql_params = (domain_id, policy)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


def insert_cms(domain_id, cms_system):
    sql = """REPLACE INTO aau.identifiedcms (domain_id, cms_system, discovered) VALUES (%s, %s, NOW())"""
    sql_params = (domain_id, cms_system)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


fetch_cursor.execute("SELECT domain_id, header FROM aau.httpheaders")
row = fetch_cursor.fetchone()

progress_bar = ProgressBar(number_of_headers, bar_length=100)
progress_bar.start()
progress_point = 0

while row is not None:
    progress_point += 1
    progress_bar.update(progress_point)
    headers = row[1].split("\n")
    for header in headers:
        if header == "":
            continue
        key_value = header.split(":")
        if key_value[1].strip() == "":
            continue
        if key_value[0].lower() == "server":
            insert_server(row[0], key_value[1].strip())
        if key_value[0].lower() == "strict-transport-security":
            insert_hsts(row[0], key_value[1].strip())
        if "x-drupal" in key_value[0].lower():
            insert_cms(row[0], 'drupal')
        if "x-aspnetmvc" in key_value[0].lower():
            insert_cms(row[0], 'aspnetmvc')
        if "sharepoint" in key_value[0].lower():
            insert_cms(row[0], 'sharepoint')
        if key_value[0].lower() == "x-powered-by":
            insert_x_poewered_by(row[0], key_value[1].strip())
            if "drupal" in key_value[1].strip().lower():
                insert_cms(row[0], 'drupal')
            if "express" in key_value[1].strip().lower():
                insert_cms(row[0], 'expressjs')
            if "statamic" in key_value[1].strip().lower():
                insert_cms(row[0], 'statematic')
            if "lynet" in key_value[1].strip().lower():
                insert_cms(row[0], 'lynet')
        if key_value[0].lower() == "x-generator":
            if "drupal" in key_value[1].lower():
                insert_cms(row[0], 'drupal')
            elif "orchard" in key_value[1].lower():
                insert_cms(row[0], 'orchard')
            else:
                print("\nHey, do you know what this is?")
                print(key_value[1])

    row = fetch_cursor.fetchone()

