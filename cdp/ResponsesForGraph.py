#!/usr/bin/env python3

import pychrome
import time
import mysql.connector
import base64
import PyChromeDevTools
import json


def do_page(page):
    starttime = time.time()
    endtime = starttime+(60*5)

    chrome = PyChromeDevTools.ChromeInterface()
    # chrome.Memory.startSampling()
    chrome.Network.enable()
    chrome.Page.enable()

    chrome.Page.navigate(url="http://" + page)
    chrome.wait_event("Page.frameStoppedLoading", timeout=60)

    db = mysql.connector.connect(
                    host="ssh.windelborg.info", 
                    user="aau", 
                    passwd="2387AXumK52aeaSA", 
                    database="aau")
    cursor = db.cursor()

    responses = []
    data = chrome.Page.captureScreenshot()

    while true:
        if time.time() > endtime:
            print("hej")
        response = chrome.wait_message(1)
        if response is None:
            continue
        curtime = time.time()-starttime
      #  responsedump = json.dumps(response)
        tupl = (curtime, "hej")
        responses.append(tupl)
    if not responses:
        return
#    sql = "INSERT INTO Responses(response_time, messages) VALUES (%s, %s)"
#    cursor.executemany(sql, responses)
    #db.commit()
    #db.close()

    # with open(page, "w") as f:
    #    for item in responses:
    #        f.write("%s\n" % str(item))


with open("top100") as file:
    for line in file:
        do_page(line.strip())

        #try:
        #    do_page(line.strip())
        #except:
        #    continue

