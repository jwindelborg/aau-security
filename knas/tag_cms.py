#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database
from configurations import repository
import time
import threading

total = 0


def tell_me_progress(total_amount):
    global total
    progress_bar = ProgressBar(total_amount, bar_length=100)
    progress_bar.start()
    while True:
        progress_bar.update(total)
        time.sleep(0.5)


def search(s):
    for key, value in repository['cms_file_path_associations']:
        if key in s:
            return value
    return "-1"


def run_process(row):
    global total
    total += 1
    database.done_tag_cms(row[0])

    cms = search(row[1])
    if cms != "-1":
        database.insert_cms(row[0], cms)


def run():
    number_of_headers = database.count_rows('domain_has_javascripts', True)
    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, url "
                   "FROM " + database.database + ".domain_has_javascripts "
                                                 "WHERE is_external = 1 AND javascript_hash NOT IN (SELECT javascript_hash FROM aau.tag_cms_history)")
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    while True:
        if threading.active_count() - 1 < 10:
            threading.Thread(target=run_process(), args=(rows.pop()), ).start()
