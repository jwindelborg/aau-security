#!/usr/bin/env python3

import argparse
import retirejs
import tag_cms
import tag_from_headers
import testssl


def parser():
    p = argparse.ArgumentParser(description="KNAS's Not A Script!")
    p.add_argument("--retirejs", dest='retirejs', nargs='bool', action='store_true', help='Run retirejs')
    p.add_argument("--tag-cms", dest='tagcms', nargs='bool', action='store_true', help='Scan JavaScript URLs to identify CMS')
    p.add_argument("--tag-from-head", dest='tagfromhead', nargs='bool', action='store_true', help='Scan headers to identify CMS')
    p.add_argument("--scan-ssl", dest='scanssl', nargs='bool', action='store_true', help='No, this is illegal')
    return p.parse_args()


def main():
    args = parser()
    if args.retirejs:
        retirejs.run()
    if args.tagcms():
        tag_cms.run()
    if args.tagsfromhead():
        tag_from_headers.run()
    if args.scanssl():
        testssl.process_batch(7)


if __name__ == "__main__":
    main()
