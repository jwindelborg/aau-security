#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database
from configurations import repository


def search(s):
    for key, value in repository['cms_file_path_associations']:
        if key in s:
            return value
    return "-1"


def run():
    number_of_headers = database.count_rows('domain_has_javascripts', True)
    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, url FROM aau.domain_has_javascripts WHERE is_external = 1")
    row = cursor.fetchone()
    progress_bar = ProgressBar(number_of_headers, bar_length=100)
    progress_bar.start()
    progress_point = 0

    while row is not None:
        progress_point += 1
        progress_bar.update(progress_point)

        cms = search(row[1])
        if cms != "-1":
            database.insert_cms(row[0], cms)

        row = cursor.fetchone()

    cursor.close()
    db.close()
