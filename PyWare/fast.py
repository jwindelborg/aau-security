#!/usr/bin/env python3

import subprocess
import threading

with open('all_malware') as f:
    lines = f.read().splitlines()

running = 0


def unugly(filename):
    global running
    running = running + 1
    print("Start tread {}".format(running))
    js = subprocess.run(['unuglifyjs', filename], stdout=subprocess.PIPE)
    js = str(js.stdout)
    js = js.replace("\\n", "\n")
    out_name = filename.rsplit('/', 1)[1]
    with open("out_dir/" + out_name, "w") as text_file:
        text_file.write("{0}".format(js))
    print("End tread {}".format(running))
    running = running - 1


while True:
    if running < 7:
        threading.Thread(target=unugly,
                         args=(lines.pop(0),),
                         ).start()
