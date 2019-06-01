#!/usr/bin/env python3

import argparse
import testssl
import sys
import threading


def parser():
    p = argparse.ArgumentParser(description="KNAS's Not A Script!")
    p.add_argument("--retirejs", dest='retirejs', action='store_true', help='Run retirejs')
    p.add_argument("--tag-cms", dest='tagcms', action='store_true', help='Scan JavaScript URLs to identify CMS')
    p.add_argument("--tag-from-head", dest='tagfromhead', action='store_true', help='Scan headers to identify CMS')
    p.add_argument("--wpscan", dest='wpscan', action='store_true', help='Scan for WordPress vulnerabilities')
    p.add_argument("-p", dest='make_parallel', action='store_true', default=False, help='Process in parallel')
    p.add_argument("--threads", dest='threads', action='store', default=3, required=False, type=int, metavar='[3]', help='How many threads to run')
    p.add_argument("--scan-ssl", dest='scan_ssl', action='store_true', help='No, this is illegal')
    p.add_argument("--ssl-threads", dest='sslthreads', action='store', required=False, type=int, default=7, metavar='[7]', help='How many SSL scan threads to run')
    p.add_argument("--ssl-locks", dest='ssllocks', action='store', required=False, type=int, default=100, metavar='[100]', help='How many domains to lock at a time')
    p.add_argument("--scan-server-header", dest='linkservervuln', action='store_true', required=False, help='Add vulnerabilities to existing server softwares')
    return p, p.parse_args()


def run_module(action):
    _module = __import__(action)
    _module.run()


def make_job_list(args):
    jobs = []
    if args.retirejs:
        jobs.append('retirejs')
    if args.tagcms:
        jobs.append('tag_cms')
    if args.tagfromhead:
        jobs.append('tag_from_headers')
    if args.wpscan:
        jobs.append('wordpress')
    if args.linkservervuln:
        jobs.append('link_server_vulnerability')
    return jobs


def run_parallel_jobs(jobs, threads):
    while len(jobs) > 0:
        if threading.active_count()-1 < threads:
            threading.Thread(target=run_module, args=(jobs.pop(),), ).start()


def validate_args(pars, args):
    if not len(sys.argv) > 1:
        pars.print_help()
        exit()

    if args.sslthreads != 7 and not args.scan_ssl:
        exit("You should make up your mind!")
    if args.ssllocks != 100 and not args.scan_ssl:
        exit("You should make up your mind!")
    if args.make_parallel and args.scan_ssl:
        exit("Sorry -p and --scan-ssl is currently not supported together")


def main():
    pars, args = parser()
    validate_args(pars, args)

    jobs = make_job_list(args)

    if args.make_parallel:
        run_parallel_jobs(jobs, args.threads)
    else:
        for job in jobs:
            run_module(job)

    if args.scan_ssl:
        testssl.run(args.sslthreads, args.ssllocks)


if __name__ == "__main__":
    main()
