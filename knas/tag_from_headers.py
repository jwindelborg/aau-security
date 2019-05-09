#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database
import linkservervuln

def x_power_search(s):
    associations = [
        ("drupal", "drupal"),
        ("express", "expressjs"),
        ("statamic", "statamic"),
        ("lynet", "lynet")
    ]
    for key, value in associations:
        if key in s:
            return value
    return "-1"


def x_generator_search(s):
    associations = [
        ("drupal", "drupal"),
        ("orchard", "orchard"),
        ("synkron", "synkron")
    ]
    for key, value in associations:
        if key in s:
            return value
    return "-1"


def key_clue_search(s):
    associations = [
        ("x-drupal", "drupal"),
        ("x-aspnetmvc", "aspnetmvc"),
        ("sharepoint", "sharepoint")
    ]
    for key, value in associations:
        if key in s:
            return value
    return "-1"


def run():
    number_of_headers = database.count_rows("httpheaders")
    progress_bar = ProgressBar(number_of_headers, bar_length=100)
    progress_bar.start()
    progress_point = 0

    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, header FROM aau.httpheaders")
    row = cursor.fetchone()

    while row is not None:
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
                database.insert_server(domain_id, value)
                linkservervuln.run_list(value)
            if key == "strict-transport-security":
                database.insert_hsts(domain_id, value)

            key_clue = key_clue_search(key)
            if key_clue != "-1":
                database.insert_cms(domain_id, key_clue)
            if key == "x-powered-by":
                database.insert_x_poewered_by(domain_id, value)
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

        row = cursor.fetchone()
    cursor.close()
    db.close()
