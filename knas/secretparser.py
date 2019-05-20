#!/usr/bin/env python3
import os


def secretparser(secret):
    path = os.path.join(os.path.dirname(__file__), "../.env")

    with open(path) as f:
        for line in f:
            if secret in line:
                return line.replace(secret + "=", "").replace("\n", "")
