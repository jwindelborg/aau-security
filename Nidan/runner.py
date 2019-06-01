#!/usr/bin/env python3

import subprocess
import threading
import socket
import sys


def run_my_nidan(name, worker, port):
    while True:
        proc = subprocess.Popen(["./nidan", "--name", str(name), "-w", str(worker), "-p", str(port)],)
        proc.wait()


def main():
    if sys.argv[1] is not "":
        if str.isdigit(sys.argv[1]):
            threads = int(sys.argv[1])
        else:
            exit("invalid argument. Please input number of desired number of instances")
    else:
        threads = 5
    name = "nidanfull"
    worker = socket.gethostname()
    for i in range(threads):
        threading.Thread(target=run_my_nidan, args=(name, worker + str(i), str(9221+i)), ).start()


if __name__ == '__main__':
    main()

