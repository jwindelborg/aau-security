#!/usr/bin/env python3

import argparse
import retirejs
import tag_cms
import tag_from_headers
import testssl
import sys
import threading


def parser():
    p = argparse.ArgumentParser(description="KNAS's Not A Script!")
    p.add_argument("--retirejs", dest='retirejs', action='store_true', help='Run retirejs')
    p.add_argument("--tag-cms", dest='tagcms', action='store_true', help='Scan JavaScript URLs to identify CMS')
    p.add_argument("--tag-from-head", dest='tagfromhead', action='store_true', help='Scan headers to identify CMS')
    p.add_argument("-p", dest='make_parallel', action='store_true', default=False, help='Process in parallel')
    p.add_argument("--threads", dest='threads', action='store', default=3, required=False, type=int, metavar='[3]', help='How many threads to run')
    p.add_argument("--scan-ssl", dest='scan_ssl', action='store_true', help='No, this is illegal')
    p.add_argument("--ssl-threads", dest='sslthreads', action='store', required=False, type=int, default=7, metavar='[7]', help='How many SSL scan threads to run')
    p.add_argument("--ssl-locks", dest='ssllocks', action='store', required=False, type=int, default=100, metavar='[100]', help='How many domains to lock at a time')
    return p, p.parse_args()


def run_parallel_action(action):
    if action == 'retirejs':
        retirejs.run()
    if action == 'tagcms':
        tag_cms.run()
    if action == 'tagfromhead':
        tag_from_headers.run()


def run_parallel(args):
    actions_desired = []
    if args.retirejs:
        actions_desired.append('retirejs')
    if args.tagcms:
        actions_desired.append('tagcms')
    if args.tagfromhead:
        actions_desired.append('tagfromhead')

    while True:
        if len(actions_desired) < 1:
            break
        if threading.active_count()-1 < args.threads:
            threading.Thread(target=run_parallel_action, args=(actions_desired.pop(),), ).start()


def main():
    pars, args = parser()

    if not len(sys.argv) > 1:
        pars.print_help()
        exit()

    if args.sslthreads != 7 and not args.scan_ssl:
        print("You should make up your mind!")
        exit()
    if args.ssllocks != 100 and not args.scan_ssl:
        print("You should make up your mind!")
        exit()
    if args.make_parellel and args.scan_ssl:
        print("Sorry -p and --scan-ssl is currently not supported together")
        exit()

    if args.make_parallel:
        run_parallel(args)
    else:
        if args.retirejs:
            retirejs.run()
        if args.tagcms:
            tag_cms.run()
        if args.tagfromhead:
            tag_from_headers.run()
        if args.scan_ssl:
            testssl.process_batch(args.sslthreads, args.ssllocks)


if __name__ == "__main__":
    main()
