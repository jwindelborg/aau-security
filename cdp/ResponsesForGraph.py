#!/usr/bin/env python3

import pychrome
import time
import mysql.connector


def do_page(page):
    starttime = time.time()
    endtime = starttime+(60*5)

    chrome = PyChromeDevTools.ChromeInterface()
    chrome.Memory.startSampling()
    chrome.Network.enable()
    chrome.Page.enable()

    chrome.Page.navigate(url="http://" + page)
    chrome.wait_event("Page.frameStoppedLoading", timeout=60)

    responses = []

    db = mysql.connector.connect(
                    host="ssh.windelborg.info", 
                    user="aau", 
                    passwd="2387AXumK52aeaSA", 
                    database="aau")
    cursor = db.cursor()

    while 1==1:
        if(time.time() >= endtime):
            break
        response = chrome.wait_message(10)
        letime = time.time()-starttime
        tupl = (letime,response)
        responses.append(tupl)

    sql = "INSERT INTO Responses (response_time, message) VALUES (%s, %s)"
    cursor.executemany(sql,responses)
    db.commit()
    db.close()

    with open(page, "w") as f:
        for item in responses:
            f.write("%s\n" % str(item))

with open("top100") as file:
    for line in file:
        try:
            do_page(line.strip())
        except:
            continue

