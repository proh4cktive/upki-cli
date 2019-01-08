#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys, os, re
import argparse, logging

import requests

from phkLogger import PHKLogger

class UPKI_Client:
    def __init__(self, logger, options, verbose=True):
        
        self._logger = logger

        self._verbose = verbose

        try:
            self._log_level = options['log_level']
        except KeyError:
            self._log_level = logging.INFO

        try:
            self._certs_dir = options['certs_dir']
            if not os.path.isdir(self._certs_dir):
                raise Exception('Certificate directory does not exists')
            if not os.access(self._certs_dir, os.W_OK):
                raise Exception('Certificate directory is not writable')
        except KeyError:
            raise Exception('Certificate directory must be set')

        try:
            self._ca_dir = options['ca_dir']
            if not os.path.isdir(self._ca_dir):
                raise Exception('CA Certificate directory does not exists')
            if not os.access(self._ca_dir, os.W_OK):
                raise Exception('CA Certificate directory is not writable')
        except KeyError:
            raise Exception('CA certificate directory must be set')

        try:
            self._ra_url = options['url']
        except KeyError:
            raise Exception('RA url must be set')

        try:
            self._dn = options['name']
        except KeyError:
            raise Exception('Client name is mandatory')

        self.headers = {'User-Agent':'uPKI client agent'}
        client_crt   = os.path.join(self._certs_dir, 'client.crt')
        client_key   = os.path.join(self._certs_dir, 'client.key')
        self.certs   = (client_crt, client_key)
        self.ca_cert = os.path.join(self._ca_dir,'upki.crt')

    def _output(self, message, level=None):
        if level is None:
            level = self._log_level
        self._logger.write(message, level=level)

    def _request(self, url):
        try:
            r = requests.get(url, verify=self.ca_cert, headers=self.headers, cert=self.certs)
        except Exception as err:
            raise Exception('Unable to get init command: {e}'.format(e=err))

        try:
            data = r.json()
        except ValueError as err:
            raise Exception('Unable to parse JSON answer; {e}'.format(e=err))

        return data

    def initialize(self):
        try:
            self._output('Request private key and CSR command')
            data = self._request(self._ra_url + '/private/magic')
        except Exception as err:
            raise Exception(err)

        print data

    def sign(self):
        try:
            self._output('Request certificate')
            data = self._request(self._ra_url + '/certify')
        except Exception as err:
            raise Exception(err)

        print data

    def renew(self):
        try:
            self._output('Renew certificate')
            data = self._request(self._ra_url + '/private/renew')
        except Exception as err:
            raise Exception(err)

        print data


def main(argv):
    BASE_DIR    = os.path.join(os.path.expanduser("~"), '.upki')
    CERT_DIR    = os.path.join(BASE_DIR, 'certs')
    CA_DIR      = os.path.join(BASE_DIR, 'ca-certificates')
    LOG_FILE    = ".cli.log"
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
    parser.add_argument("-u", "--url", help="Define the RA url", required=True)
    parser.add_argument("-n", "--name", help="Define the requested DN name", required=True)
    parser.add_argument("-j", "--json", help="Output result in json", action="store_true")
    parser.add_argument("-c", "--certs", help="set the certificate directory where key, csr and crt are stored. Default is {c}".format(c=CERT_DIR))
    parser.add_argument("-a", "--auth", help="set the CA certificate directory where certificate is stored. Default is {c}".format(c=CA_DIR))

    args = parser.parse_args()

    # Parse common options
    if args.quiet:
        VERBOSE = False

    if args.debug:
        LOG_LEVEL = logging.DEBUG

    if args.json:
        OUTPUT = 'json'
    
    # Generate logger object
    logger = PHKLogger(os.path.join(BASE_DIR,LOG_FILE), LOG_LEVEL, proc_name="upki", verbose=VERBOSE)
    logger.info("\t\t..:: µPKI Client ::..", color="WHITE", light=True)
    logger.info("version: {v}".format(v=metadata['version']), color="WHITE")

    if args.certs:
        CERT_DIR = args.certs

    if args.auth:
        CA_DIR = args.auth

    options = {'certs_dir': CERT_DIR, 'ca_dir': CA_DIR, 'url': args.url, 'name': args.name, 'log_level':LOG_LEVEL}

    try:
        client = UPKI_Client(logger, options, verbose=VERBOSE)
    except Exception as err:
        logger.error(err)
        return False

    if not os.path.isfile(os.path.join(CERT_DIR, 'client.key')):
        # Generate Key and CSR
        try:
            client.initialize()
        except Exception as err:
            logger.error(err)
    elif not os.path.isfile(os.path.join(CERT_DIR, 'client.crt')):
        # Request certificate
        try:
            client.sign()
        except Exception as err:
            logger.error(err)
    else:
        # Renew existing certificate
        try:
            client.renew()
        except Exception as err:
            logger.error(err)
    
if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.stdout.write('\nBye.\n')