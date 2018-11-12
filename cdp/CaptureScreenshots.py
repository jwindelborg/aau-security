#!/usr/bin/env python3

import pychrome
import base64

def do_page(page):
    browser = pychrome.Browser(url="http://127.0.0.1:9222")
    tab = browser.new_tab()

    def request_will_be_sent(**kwargs):
        print("loading: %s" % kwargs.get('request').get('url'))


    tab.set_listener("Network.requestWillBeSent", request_will_be_sent)

    tab.start()
    tab.call_method("Network.enable")
    tab.call_method("Page.navigate", url="http://" + page, _timeout=5)
    tab.wait(2)
    data = tab.Page.captureScreenshot()
    with open("%s.png" % page, "wb") as fd:
        fd.write(base64.b64decode(data['data']))

    tab.wait(2)
    tab.stop()

    browser.close_tab(tab)


with open("dk-domains") as file:
    for line in file:
        try:
            do_page(line.strip())
        except:
            continue
