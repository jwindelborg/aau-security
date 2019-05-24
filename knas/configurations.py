#!/usr/bin/env python3

import os
import json


def configuration_parser(secret):
    path = os.path.join(os.path.dirname(__file__), "../.env")

    with open(path) as f:
        for line in f:
            if secret in line:
                return line.replace(secret + "=", "").replace("\n", "")


with open('repository.json') as data_file:
    repository = json.load(data_file)
