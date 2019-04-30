#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import mysql.connector

count_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")
fetch_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")
insert_db = mysql.connector.connect(host="142.93.109.128", user="aau", passwd="2387AXumK52aeaSA")

insert_cursor = insert_db.cursor()
count_cursor = count_db.cursor()
fetch_cursor = fetch_db.cursor()


count_cursor.execute("SELECT COUNT(*) FROM aau.javascriptdomains")
number_of_headers = count_cursor.fetchall()[0][0]
count_cursor.close()
count_db.close()


def insert_cms(domain_id, cms_system):
    sql = """REPLACE INTO aau.identifiedcms (domain_id, cms_system, discovered) VALUES (%s, %s, NOW())"""
    sql_params = (domain_id, cms_system)
    insert_cursor.execute(sql, sql_params)
    insert_db.commit()


fetch_cursor.execute("SELECT domain_id, url FROM aau.javascriptdomains")
row = fetch_cursor.fetchone()

progress_bar = ProgressBar(number_of_headers, bar_length=100)
progress_bar.start()
progress_point = 0

while row is not None:
    progress_point += 1
    progress_bar.update(progress_point)
    if "wp-content" in row[1]:
        insert_cms(row[0], 'wordpress')
    if "wp-includes" in row[1]:
        insert_cms(row[0], 'wordpress')
    if "sitevision" in row[1]:
        insert_cms(row[0], 'sitevision')
    if "drupal" in row[1]:
        insert_cms(row[0], 'drupal')
    if "/sites/default/files/" in row[1]:
        insert_cms(row[0], 'drupal')
    if "/catalog/view/theme/" in row[1]:
        insert_cms(row[0], 'opencart')
    if "com_virtuemart" in row[1]:
        insert_cms(row[0], 'joomla_virtuemart')
    if "sitecore" in row[1]:
        insert_cms(row[0], 'sitecore')
    if "symfony/" in row[1]:
        insert_cms(row[0], 'symfony')
    if "magestore" in row[1]:
        insert_cms(row[0], 'magento')

    row = fetch_cursor.fetchone()

