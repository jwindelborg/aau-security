#!/usr/bin/env python3

import PyChromeDevTools
import time


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

    while 1==1:
        if(time.time() >= endtime):
            break
        response = chrome.wait_message(10)
        letime = time.time()-starttime
        tupl = (letime,response)
        responses.append(tupl)

    with open(page, "w") as f:
        for item in responses:
            f.write("%s\n" % str(item))


with open("top100") as file:
    for line in file:
        try:
            do_page(line.strip())
        except:
            continue
