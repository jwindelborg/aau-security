#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database
import link_server_vulnerability
from configurations import repository


def x_power_search(s):
    for key, value in repository['x_power_cms_associations']:
        if key in s:
            return value
    return "-1"


def x_generator_search(s):
    for key, value in repository['x_generator_associations']:
        if key in s:
            return value
    return "-1"


def key_clue_search(s):
    for key, value in repository['header_key_associations']:
        if key in s:
            return value
    return "-1"


def run():
    number_of_headers = database.count_rows("http_headers")
    progress_bar = ProgressBar(number_of_headers, bar_length=100)
    progress_bar.start()
    progress_point = 0

    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, header FROM aau.http_headers")
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    for row in rows:
        progress_point += 1
        progress_bar.update(progress_point)
        headers = row[1].split("\n")
        for header in headers:

            if header == "":
                continue

            key_value = header.split(":")
            key = key_value[0].lower()
            value = key_value[1].strip().lower()
            domain_id = row[0]

            if value == "":
                continue

            if key == "server":
                link_server_vulnerability.make_server_software(domain_id, value)
            if key == "strict-transport-security":
                database.insert_hsts(domain_id, value)

            key_clue = key_clue_search(key)
            if key_clue != "-1":
                database.insert_cms(domain_id, key_clue)
            if key == "x-powered-by":
                database.insert_x_powered_by(domain_id, value)
                x_result = x_power_search(value)
                if x_result != "-1":
                    database.insert_cms(domain_id, x_result)

            if key == "x-generator":
                x_gen_res = x_generator_search(value)
                if x_gen_res != "-1":
                    database.insert_cms(domain_id, x_gen_res)
                else:
                    print("\nHey, do you know what this is?")
                    print(value)
