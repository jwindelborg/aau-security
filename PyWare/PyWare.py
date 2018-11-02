#!/usr/bin/env python3

import argparse
import os
import subprocess
import re

pattern = re.compile("(var )(([a-zA-Z])([a-zA-Z0-9$_])*)( = \")(([a-zA-Z0-9$_/:%.?=&()\-\,])*)(\")")

def arg_parser():
    parser = argparse.ArgumentParser(description="Analyze javascript")
    parser.add_argument("jsfile", nargs='+', action='store', help='JavaScript file')
    return parser.parse_args()


def open_and_pretty(filename):
    FNULL = open(os.devnull, 'w')
    javascript = subprocess.run(['unuglifyjs', filename[0]], stdout=subprocess.PIPE, stderr=FNULL)
    javascript = str(javascript.stdout)
    javascript = javascript.replace('" + "', '')
    javascript = javascript.replace('" +  "', '')
    javascript = javascript.replace("\\n", "\n")

    listofvarsandvalues = []

    for vars in re.finditer(pattern, javascript):
        tpl = vars.group(2), vars.group(6)
        listofvarsandvalues.append(tpl)

    for vars in listofvarsandvalues:
        search = "(?<= )(" + vars[0] + ")(?= |;)(?! =)"
        insert_val = ' "' + vars[1] + '"'
        bla = re.compile(search)
        javascript = bla.sub(insert_val, javascript)
        javascript = javascript.replace('" + "', '')
        javascript = javascript.replace('" +  "', '')

    javascript = javascript[2:-1]
    print(javascript)


def main():
    args = arg_parser()
    open_and_pretty(args.jsfile)


if __name__ == "__main__":
    main()