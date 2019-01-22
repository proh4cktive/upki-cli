#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys, os, re, hashlib
import argparse, logging, json

import requests, subprocess

from phkLogger import PHKLogger

class UPKI_Client:
    def __init__(self, logger, options, verbose=True):
        
        self._logger   = logger
        self._verbose  = verbose
        self._unsecure = False

        try:
            self._log_level = options['log_level']
        except KeyError:
            self._log_level = logging.INFO

        try:
            self._pem = options['pem']
        except KeyError:
            self._pem = False

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
            # Remove trailing slash if needed
            if self._ra_url[-1] == '/':
                self._ra_url = self._ra_url[:-1]

            if self._ra_url.startswith('http://'):
                self._output('Using unsecured protocol "http://" is NOT recommended...', level="warning")
                while True:
                    rep = raw_input('Do you want to continue ? [y/N]')
                    if rep.lower() == 'y':
                        self._unsecure = True
                        break
                    raise Exception('Unsecure protocol refused by user.')

            elif not self._ra_url.startswith('https://'):
                self._ra_url = 'https://' + self._ra_url
        except KeyError:
            raise Exception('RA url must be set')

        try:
            self._dn = options['name']
        except KeyError:
            raise Exception('Client name is mandatory')

        try:
            self._cn = self._get_cn(self._dn)
        except Exception as err:
            raise Exception('Unable to get CN from DN: {e}'.format(e=err))

        self.headers = {'User-Agent':'uPKI client agent', 'Content-Type': 'application/json'}

        self.ca_cert = os.path.join(self._ca_dir,'upki.crt')

        self._has_ca = os.path.isfile(self.ca_cert)

        self.key_path = os.path.join(self._certs_dir, '{n}.key'.format(n=self._cn))
        self.csr_path = os.path.join(self._certs_dir, '{n}.csr'.format(n=self._cn))
        self.crt_path = os.path.join(self._certs_dir, '{n}.crt'.format(n=self._cn))
        self.pem_path = os.path.join(self._certs_dir, '{n}.pem'.format(n=self._cn))

        self._is_init = (os.path.isfile(self.key_path) and os.path.isfile(self.csr_path))
        self._is_sign = os.path.isfile(self.crt_path)

        self.certs   = (self.crt_path, self.key_path)

        # Always check CA certificate
        self.get_ca_checksum()

    def _output(self, message, level=None):
        if level is None:
            level = self._log_level
        self._logger.write(message, level=level)

    def _get_cn(self, dn):
        try:
            cn = str(dn).split('CN=')[1]
        except Exception:
            raise Exception('Unable to get CN from DN string')

        return cn

    def _request(self, url, data=None):

        try:
            if self._unsecure:
                r = requests.post(url, data=json.dumps(data), headers=self.headers)
            else:
                # r = requests.post(url, data=json.dumps(data), verify=self.ca_cert, headers=self.headers, cert=self.certs)
                r = requests.post(url, data=json.dumps(data), verify=False, headers=self.headers)
        except Exception as err:
            raise Exception('Unable to get init command: {e}'.format(e=err))

        if r.status_code != 200:
            raise Exception(r.content)           

        return r

    def start(self):
        # Initialize if needed
        if not self._is_init:
            self.initialize()
        
        # Either sign or renew
        if not self._is_sign:
            self.sign()
        else:
            self.renew()

    def get_ca_checksum(self):
        try:
            self._output('Get CA certificate')
            if self._unsecure:
                data = requests.get(self._ra_url + '/certs/ca.crt', headers=self.headers)
            else:
                # data = requests.get(self._ra_url + '/certs/ca.crt', verify=self.ca_cert, headers=self.headers)
                data = requests.get(self._ra_url + '/certs/ca.crt', verify=False, headers=self.headers)
        except Exception as err:
            raise Exception(err)

        if data.status_code != 200:
            raise Exception(data.content)           

        # Init hash function
        received = hashlib.sha256(data.content).hexdigest()
        self._output('CA certificate hash received: {s}'.format(s=received), level='debug')

        if self._has_ca:
            with open(self.ca_cert, 'rb') as f:
                raw = f.read()
            
            found = hashlib.sha256(raw).hexdigest()
            
            if found != received:
                self._output('OLD CA certificate hash was: {s}'.format(s=found), level='debug')
                self._output('NEW CA certificate received!', level="warning")
                while True:
                    rep = raw_input('Would you like to update it ? [y/N]')
                    if rep.lower() == 'y':
                        break
                    raise Exception('CA certificate change refused by user.')
            else:
                # If nothing has changed abort
                self._output('CA certificate unchanged', level='debug')
                return True
        else:
            self._output('CA certificate first installation', level="warning")

        # Should return sha256 of cert
        with open(self.ca_cert,'wt') as f:
            f.write(data.content)

        return True

    def initialize(self):
        try:
            self._output('Request private key and CSR command')
            rep = self._request(self._ra_url + '/private/magic', data={'dn': self._dn})
        except Exception as err:
            raise Exception(err)

        try:
            data = rep.json()
        except ValueError as err:
            try:
                error = rep.text
                raise Exception(error)
            except AttributeError:
                raise Exception('Unable to parse JSON answer; {e}'.format(e=err))

        try:
            cmd = data['cmd']
        except KeyError:
            raise Exception('Unable to get magic command')

        try:
            p = subprocess.Popen(cmd, cwd=self._certs_dir, shell=True)
            p.wait()
        except Exception as err:
            raise Exception('Unable to execute magic command: {e}'.format(e=err))

        # Protect key and csr from re-write
        try:
            os.chmod(self.key_path, 0400)
            os.chmod(self.csr_path, 0400)
        except Exception as err:
            raise Exception('Unable to protect key and certificate request')

        return True

    def sign(self):
        
        with open(self.csr_path, 'rt') as f:
            csr = f.read()

        try:
            self._output('Request certificate')
            data = self._request(self._ra_url + '/certify', data={'csr':csr})
        except Exception as err:
            raise Exception(err)

        with open(self.crt_path, 'wb') as f:
            self._output('Writing certificate to {p}'.format(p=self.crt_path))
            f.write(data.content)

        # Protect key and csr from re-write
        try:
            os.chmod(self.crt_path, 0400)
        except Exception as err:
            raise Exception('Unable to certificate')

        if self._pem:
            self._output('Generate PEM file with key and certificates', level='warning')
            with open(self.crt_path , 'rt') as f:
                crt_content = f.read()
            with open(self.key_path, 'rt') as f:
                key_content = f.read()

            with open(self.pem_path, 'wb') as f:
                f.write(crt_content)
                f.write(key_content)

            # Protect key and csr from re-write
            try:
                os.chmod(self.pem_path, 0400)
            except Exception as err:
                raise Exception('Unable to protect certificate pem file')

        return True

    def renew(self):
        if not (self._is_init or self._is_sign):
            raise Exception('You can not renew an unexisting certificate')

        if self._unsecure:
            raise Exception('Can not renew certificate with unsecured protocol')

        try:
            self._output('Renew certificate')
            # data = self._request(self._ra_url + '/private/renew')
            # data = requests.get(self._ra_url + '/secure/renew', verify=self.ca_cert, headers=self.headers, cert=self.certs)
            data = requests.get(self._ra_url + '/secure/renew', verify=False, headers=self.headers, cert=self.certs)
        except Exception as err:
            raise Exception(err)

        if data.status_code != 200:
            raise Exception(data.content)           

        # Unlock protection
        try:
            os.chmod(self.crt_path, 0600)
        except Exception as err:
            raise Exception('Unable to unlock certificate protection')

        with open(self.crt_path, 'wb') as f:
            self._output('Renew certificate to {p}'.format(p=self.crt_path))
            f.write(data.content)

        # Re-enable protection
        try:
            os.chmod(self.crt_path, 0400)
        except Exception as err:
            raise Exception('Unable to protect certificate')

        if self._pem:
            # Unlock protection
            try:
                os.chmod(self.pem_path, 0600)
            except Exception as err:
                raise Exception('Unable to unlock certificate pem file protection')

            self._output('Generate PEM file with key and certificates', level='warning')
            with open(self.crt_path , 'rt') as f:
                crt_content = f.read()
            with open(self.key_path, 'rt') as f:
                key_content = f.read()

            with open(self.pem_path, 'wb') as f:
                f.write(crt_content)
                f.write(key_content)

            # Re-enable protection
            try:
                os.chmod(self.pem_path, 0400)
            except Exception as err:
                raise Exception('Unable to protect certificate pem file')

        return True


def main(argv):
    BASE_DIR    = os.path.join(os.path.expanduser("~"), '.upki')
    CERT_DIR    = os.path.join(BASE_DIR, 'certs')
    CA_DIR      = os.path.join(BASE_DIR, 'ca-certificates')
    LOG_FILE    = ".cli.log"
    LOG_LEVEL   = logging.INFO
    VERBOSE     = True
    OUTPUT      = 'cli'
    PEM         = False

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
    parser.add_argument("-p", "--pem", help="Generate a pem file", action="store_true")
    
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

    if args.pem:
        PEM = True

    options = {'certs_dir': CERT_DIR, 'ca_dir': CA_DIR, 'url': args.url, 'name': args.name, 'log_level':LOG_LEVEL, 'pem':PEM}

    try:
        client = UPKI_Client(logger, options, verbose=VERBOSE)
    except Exception as err:
        logger.error(err)
        return False

    try:
        client.start()
    except Exception as err:
        logger.error(err)
    
if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.stdout.write('\nBye.\n')