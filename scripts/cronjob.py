#!/usr/bin/env python3

import mysql.connector

host = ""
user = ""
password = ""


def get_mysql_db_cursor():
    db = mysql.connector.connect(host=host, user=user, passwd=password)
    return db, db.cursor()


def do_and_done(query, params):
    db, cursor = get_mysql_db_cursor()
    cursor.execute(query, params)
    db.commit()
    cursor.close()
    db.close()


def find_all_workers_with_locks():
    db, cursor = get_mysql_db_cursor()
    sql = "SELECT DISTINCT worker FROM aau_sample.locked_domains"
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return results


def check_if_no_activity(worker):
    db, cursor = get_mysql_db_cursor()
    sql = "SELECT ld.worker AS t, MAX(vh.created_at) FROM aau_sample.locked_domains ld LEFT OUTER JOIN aau_sample.cdp_visit_history vh ON ld.worker = vh.worker WHERE vh.created_at < DATE_ADD(NOW(), INTERVAL 200 SECOND) AND ld.worker = %s GROUP BY ld.worker"
    params = (worker, )
    cursor.execute(sql, params)
    results = cursor.fetchall()
    cursor.close()
    db.close()
    return len(results) > 0


def delete_for_worker(worker):
    sql = "DELETE FROM aau_sample.locked_domains WHERE worker = %s"
    params = (worker,)
    do_and_done(sql, params)


def cronjob():
    workers = find_all_workers_with_locks()

    for worker in workers:
        if check_if_no_activity(worker[0]):
            delete_for_worker(worker[0])


cronjob()
