#!/usr/bin/env python3

import database

with open('zonefile') as f:
    threads = 50
    increment_size = 1000

    zone_file = f.readlines()
    db, cursor = database.get_mysql_db_cursor()
    for domain in zone_file:
        sql = "INSERT INTO " + database.database + ".domains " \
              "(domain, created_at) " \
              "VALUES (%s, NOW())"
        params = (domain.rstrip(),)
        cursor.execute(sql, params)
    db.commit()
    db.close()
