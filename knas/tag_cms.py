#!/usr/bin/env python3

from ezprogress.progressbar import ProgressBar
import database


def search(s):
    associations = [
        ("/wp-content/", "wordpress"),
        ("/wp-includes/", "wordpress"),
        ("sitevision", "sitevision"),
        ("drupal", "drupal"),
        ("/sites/default/files/", "drupal"),
        ("/catalog/view/theme/", "opencart"),
        ("com_virtuemart", "joomla_virtuemart"),
        ("sitecore", "sitecore"),
        ("symfony", "symfony"),
        ("magestore", "magento")
    ]
    for key, value in associations:
        if key in s:
            return value
    return "-1"


def run():
    number_of_headers = database.count_rows('javascriptdomains')
    db, cursor = database.get_mysql_db_cursor()
    cursor.execute("SELECT domain_id, url FROM aau.javascriptdomains")
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
