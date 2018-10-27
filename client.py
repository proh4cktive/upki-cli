#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys, os, re
import argparse, logging

def main(argv):
    BASE_DIR    = os.path.join(os.path.expanduser("~"), '.upki')
    LOG_FILE    = ".upki.log"
    LOG_LEVEL   = logging.INFO
    VERBOSE     = True
    OUTPUT      = 'cli'

    # Retrieve all metadata from project
    with open("__metadata.py", 'rt') as meta_file:
        metadata = dict(re.findall(r"^__([a-z]+)__ = ['\"]([^'\"]*)['\"]", meta_file.read(), re.M))
    
    parser = argparse.ArgumentParser(description="µPki-CLI is the µPKI client.")
    parser.add_argument("-q", "--quiet", help="Output less infos", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    parser.add_argument("-l", "--log", help="Define log file (default: {f})".format(f=os.path.join(BASE_DIR,LOG_FILE)))
    parser.add_argument("-j", "--json", help="Output result in json", action="store_true")

    # Allow subparsers
    subparsers = parser.add_subparsers(title='commands')


if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.stdout.write('\nBye.\n')