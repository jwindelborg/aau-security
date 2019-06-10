#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database
import link_server_vulnerability
from configurations import repository
import threading
import time

progresses = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


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


def count_processes():
    global progresses
    count = 0
    for i in progresses:
        count += i
    return count


def tell_me_progress():
    number_of_headers = database.count_rows("http_headers")
    progress_bar = ProgressBar(number_of_headers, bar_length=100)
    progress_bar.start()
    while True:
        progress_bar.update(count_processes())
        time.sleep(0.5)


def do_part(headers_raw, index):
    global progresses

    for header_row in headers_raw:
        database.done_tag_from_header(header_row[0])
        progresses[index] += 1
        headers = header_row[1].split("\n")
        for header in headers:

            if header == "":
                continue

            key_value = header.split(":")
            key = key_value[0].lower()
            value = key_value[1].strip().lower()
            domain_id = header_row[0]

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
                    print("\nx-generator not known. If you know this, please create an issue on GitHub")
                    print(value)


def run():
    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, header "
                   "FROM " + database.database + ".http_headers WHERE domain_id NOT IN (SELECT domain_id FROM aau.tag_from_header_history)")
    header_rows = cursor.fetchall()
    cursor.close()
    db.close()

    # Calculate size
    # 642483 / 10 = ~64248
    # 64248 * 10 = 642480
    # 642483 - 642480 = 3
    size = 64248
    start_at = 0
    end_at = 64248
    for i in range(10):
        threading.Thread(target=do_part, args=(header_rows[start_at:end_at], i), ).start()
        start_at = end_at
        end_at += size

    threading.Thread(target=tell_me_progress, args=(), ).start()
    do_part(header_rows[:-3], 0)


run()
