# -*- coding:utf-8 -*-

import os
import sys
import json
import hashlib
import requests
# Prevent CLI output pollution
requests.packages.urllib3.disable_warnings()
import subprocess

import client

class Bot(object):
    def __init__(self, logger, ra_url, path, verbose=True):
        
        self._logger   = logger
        self._verbose  = verbose
        self._unsecure = False
        
        self._path   = path
        self._ra_url = ra_url
        self.ca_cert = os.path.join(self._path, 'ca.crt')
        self.crl_crt = os.path.join(self._path, 'crl.pem')
        
        try:
            self.collection = client.Collection(self._path)
        except Exception as err:
            raise Exception('Unable to initialize collection: {e}'.format(e=err))

        try:
            # Store every certificates found
            self.collection.list_nodes()
        except Exception as err:
            raise Exception('Unable to list certificates: {e}'.format(e=err))

        try:
            # Configure connection settings
            self.__setup_connection()
        except Exception as err:
            raise Exception(err)

        try:
            # Always check CA certificate
            self.get_ca_checksum()
        except Exception as err:
            raise Exception('Unable to calculate CA certificate checksum: {e}'.format(e=err))


    def __setup_connection(self):
        # Remove trailing slash if needed
        if self._ra_url[-1] == '/':
            self._ra_url = self._ra_url[:-1]

        if self._ra_url.startswith('http://'):
            self._output('Using unsecured protocol "http://" is NOT recommended...', level="warning")
            while True:
                rep = input('Do you want to continue ? [y/N]')
                if rep.lower() == 'y':
                    self._unsecure = True
                    break
                raise Exception('Unsecure protocol refused by user.')

        elif not self._ra_url.startswith('https://'):
            self._ra_url = 'https://' + self._ra_url
        
        self.headers = {'User-Agent':'uPKI client agent', 'Content-Type': 'application/json'}

    def __request(self, url, data=None, cert=None, verb='GET', verify=False, text=False):
        if verb.upper() not in ['GET','POST']:
            raise NotImplementedError('Unsupported action')

        action = getattr(requests, verb.lower())
        json_data = json.dumps(data) if data else None

        try:
            r = action(url, data=json_data, headers=self.headers, verify=verify, cert=cert)
        except Exception as err:
            raise Exception('Unable to make TLS request: {e}'.format(e=err))

        if r.status_code != 200:
            raise Exception(r.content)

        # For CA and CRL certificates
        if text:
            return r.text

        try:
            data = r.json()
        except ValueError as err:
            try:
                error = r.text
                raise Exception(error)
            except AttributeError:
                raise Exception('Unable to parse JSON answer; {e}'.format(e=err)) 

        if data.get('status') != 'success':
            raise Exception("HTTP(S) Request Error: {e}".format(e=data.get('message')))

        return data

    def __execute(self, cmd, cwd=None):
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self._path, executable='/bin/bash')
            p.wait()
        except Exception as err:
            raise Exception('Unable to execute command: {e}'.format(e=err))


    def _output(self, message, level=None):
        try:
            self._logger.write(message, level=level)
        except Exception as err:
            sys.out.write('Unable to log: {e}'.format(e=err))

    def get_ca_checksum(self):
        try:
            self._output('Check CA certificate', level="DEBUG")
            ca_pem = self.__request(self._ra_url + '/certs/ca.crt', text=True)
        except Exception as err:
            raise Exception(err)

        # Init hash function
        received = hashlib.sha256(ca_pem.encode('utf-8')).hexdigest()
        self._output('CA certificate hash received: {s}'.format(s=received), level='debug')

        if os.path.isfile(self.ca_cert):
            with open(self.ca_cert, 'rt') as f:
                raw = f.read()
            
            found = hashlib.sha256(raw.encode('utf-8')).hexdigest()
            
            if found != received:
                self._output('OLD CA certificate hash was: {s}'.format(s=found), level='debug')
                self._output('NEW CA certificate received!', level="warning")
                while True:
                    rep = input('Would you like to update it ? [y/N]')
                    if rep.lower() == 'y':
                        break
                    raise Exception('CA certificate change refused by user.')
                # Remove CA protection
                try:
                    os.chmod(self.ca_cert, 0o600)
                except Exception as err:
                    raise Exception('Unable to remove CA certificate protection')
            else:
                # If nothing has changed abort
                self._output('CA certificate unchanged', level='debug')
                return True
        else:
            self._output('CA certificate first installation', level="warning")

        # Rewrite CA certificate
        with open(self.ca_cert,'wt') as f:
            f.write(ca_pem)

        # Protect CA certificate
        try:
            os.chmod(self.ca_cert, 0o444)
        except Exception as err:
            raise Exception('Unable to protect CA certificate')

        return True

    def add_node(self, name, profile, sans=[], p12=False, passwd=None):
        if name is None:
            name = input('Enter your node name (CN): ')
        if profile is None:
            profile = input('Enter your profile: ')

        try:
            self._output('Request openssl command', level="DEBUG")
            data = self.__request(self._ra_url + '/magic/' + profile, data={'cn': name, 'sans': sans}, verify=self.ca_cert, verb="POST")
        except Exception as err:
            raise Exception(err)

        try:
            self.collection.register(name, profile, sans, p12=p12, passwd=passwd)
        except Exception as err:
            raise Exception('Unable to add node: {e}'.format(e=err))

        try:
            cmd = data['command']
        except KeyError:
            raise Exception('Unable to get magic command')

        try:
            self.__execute(cmd)
        except Exception as err:
            raise Exception('Unable to execute magic command: {e}'.format(e=err))

        # Store filenames
        key_file = os.path.join(self._path, "{p}.{n}.key".format(p=profile, n=name))
        req_file = os.path.join(self._path, "{p}.{n}.csr".format(p=profile, n=name))
        crt_file = os.path.join(self._path, "{p}.{n}.crt".format(p=profile, n=name))
        
        try:
            # Protect key and csr from re-write
            os.chmod(key_file, 0o440)
            os.chmod(req_file, 0o444)
        except Exception as err:
            raise Exception('Unable to protect key and certificate request')

        with open(req_file, 'rt') as f:
            csr = f.read()

        try:
            self._output('Request certificate', level="DEBUG")
            data = self.__request(self._ra_url + '/certify', data={'CSR':csr}, verb="POST", verify=self.ca_cert)
        except Exception as err:
            raise Exception(err)

        try:
            data['certificate']
        except KeyError:
            raise Exception('Missing certificate')

        try:
            self.collection.sign(profile, name)
        except Exception as err:
            raise Exception('Unable to sign certificate: {e}'.format(e=err))

        with open(crt_file, 'wb') as f:
            self._output('Writing certificate to {p}'.format(p=crt_file))
            f.write(data['certificate'].encode('utf-8'))

        try:
            # Protect certificate from re-write
            os.chmod(crt_file, 0o444)
        except Exception as err:
            raise Exception('Unable to protect certificate')

        self._output('Generate PEM file with key and certificates')
        with open(crt_file , 'rt') as f:
            crt_content = f.read()
        with open(key_file, 'rt') as f:
            key_content = f.read()

        pem_file = os.path.join(self._path, "{p}.{n}.pem".format(p=profile, n=name))
        with open(pem_file, 'wt') as f:
            f.write(crt_content)
            f.write(key_content)

        # Protect pem from re-write
        try:
            os.chmod(pem_file, 0o444)
        except Exception as err:
            raise Exception('Unable to protect certificate pem file')

        if p12:
            # Generate p12 certificate
            p12_file = os.path.join(self._path, "{p}.{n}.p12".format(p=profile, n=name))
            openssl_args = ['openssl','pkcs12','-export','-out',p12_file,'-inkey',key_file,'-in',crt_file,'-in',ca_cert]
            if passwd:
                self._output('Generate P12 file with password')
                openssl_args += ['-passout',"pass:{p}".format(p=passwd)]
            else:
                self._output('Generate P12 file without password', level='warning')

            try:
                self.__execute(openssl_args)
            except Exception as err:
                raise Exception('Unable to generate p12 certificate: {e}'.format(e=err))
            
            # Protect p12 from re-write
            try:
                os.chmod(p12_file, 0o444)
            except Exception as err:
                raise Exception('Unable to protect certificate p12 file')

        return True

    def renew(self):
        if self._unsecure:
            raise Exception('Can not renew certificates with unsecured protocol')

        try:
            self.collection.list_nodes()
        except Exception as err:
            raise Exception('Unable to list nodes: {e}'.format(e=err))

        if not len(self.collection.nodes):
            raise Exception('No node to renew.')

        for node in self.collection.nodes:
            try:
                # Store filenames
                key_file = os.path.join(self._path, "{p}.{n}.key".format(p=node['profile'], n=node['name']))
                req_file = os.path.join(self._path, "{p}.{n}.csr".format(p=node['profile'], n=node['name']))
                crt_file = os.path.join(self._path, "{p}.{n}.crt".format(p=node['profile'], n=node['name']))
                pem_file = os.path.join(self._path, "{p}.{n}.pem".format(p=node['profile'], n=node['name']))
            except KeyError:
                raise Exception('Missing mandatory params')

            try:
                self._output('Renew certificate {n} ({p})'.format(n=node['name'], p=node['profile']))
                data = self.__request(self._ra_url + '/clients/renew', verify=self.ca_cert, cert=(crt_file, key_file))
            except Exception as err:
                self._output('Unable to renew certificate: {e}'.format(e=err), level="WARNING")
                continue

            try:
                if not data['renew']:
                    self._output(data['reason'], level="WARNING")
                    continue
                data['certificate']
            except KeyError:
                raise Exception('Missing certificate')

            try:
                # Unlock protection
                os.chmod(crt_file, 0o600)
            except Exception as err:
                raise Exception('Unable to unlock certificate protection')

            with open(crt_file, 'wb') as f:
                self._output('Renew certificate to {p}'.format(p=crt_file), level="DEBUG")
                f.write(data['certificate'].encode('utf-8'))

            try:
                # Re-enable protection
                os.chmod(crt_file, 0o444)
            except Exception as err:
                raise Exception('Unable to protect certificate')

            try:
                # Unlock protection
                os.chmod(pem_file, 0o600)
            except Exception as err:
                raise Exception('Unable to unlock certificate pem file protection')

            self._output('Re-Generate PEM file with key and new certificate')
            with open(crt_file , 'rt') as f:
                crt_content = f.read()
            with open(key_file, 'rt') as f:
                key_content = f.read()

            with open(pem_file, 'wt') as f:
                f.write(crt_content)
                f.write(key_content)

            try:
                # Re-enable protection
                os.chmod(pem_file, 0o444)
            except Exception as err:
                raise Exception('Unable to protect certificate pem file')

            if node['p12']:
                p12_file = os.path.join(self._path, "{p}.{n}.p12".format(p=node['profile'], n=node['name']))
                # Generate p12 certificate
                openssl_args = ['openssl','pkcs12','-export','-out',p12_file,'-in',crt_file,'-inkey',key_file]
                if passwd:
                    self._output('Re-Generate P12 file with password')
                    openssl_args += ['-passout',"pass:{p}".format(p=passwd)]
                else:
                    self._output('Re-Generate P12 file without password', level='warning')

                try:
                    # Unlock protection
                    os.chmod(p12_file, 0o600)
                except Exception as err:
                    raise Exception('Unable to unlock certificate p12 file protection')

                try:
                    self.__execute(openssl_args)
                except Exception as err:
                    raise Exception('Unable to generate p12 certificate: {e}'.format(e=err))

                try:
                    # Re-enable protection
                    os.chmod(p12_file, 0o444)
                except Exception as err:
                    raise Exception('Unable to protect certificate p12 file')

        return True

    def crl(self):
        try:
            self._output('Retrieve CRL', level="DEBUG")
            crl_pem = self.__request(self._ra_url + '/certs/crl.pem', text=True)
        except Exception as err:
            raise Exception(err)

        # Rewrite CRL file
        with open(self.crl_crt,'wt') as f:
            f.write(crl_pem)

        return True

    def list(self):

        try:
            nodes = self.collection.list_nodes()
        except Exception as err:
            raise Exception('Unable to retrieve nodes: {e}'.format(e=err))

        if not len(nodes):
            self._output('No node found in config.')
            return False

        self._output('\t\t..:: Nodes found in config ::..')
        for i, node in enumerate(nodes):
            self._output('\t- {n}\t({p})'.format(n=node['name'],p=node['profile']))

        return True

    def delete(self, name, profile):
        if name is None:
            name = input('Enter node name to delete (CN): ')
        if profile is None:
            profile = input('Enter node profile to delete: ')

        try:
            node = self.collection.get_node(name, profile)
        except Exception as err:
            raise Exception('Unable to load node: {e}'.format(e=err))

        if node is None:
            raise Exception('Node does not exists.')

        try:
            # Ensure params exists
            name    = node['name']
            profile = node['profile']
            p12     = node['p12']
        except KeyError:
            raise Exception('Missing mandatory params')

        # Store filenames
        key_file = os.path.join(self._path, "{p}.{n}.key".format(p=profile, n=name))
        req_file = os.path.join(self._path, "{p}.{n}.csr".format(p=profile, n=name))
        crt_file = os.path.join(self._path, "{p}.{n}.crt".format(p=profile, n=name))
        pem_file = os.path.join(self._path, "{p}.{n}.pem".format(p=profile, n=name))
        p12_file = os.path.join(self._path, "{p}.{n}.p12".format(p=profile, n=name))

        try:
            self.collection.remove(name, profile)
        except Exception as err:
            raise Exception('Unable to add node: {e}'.format(e=err))

        if os.path.isfile(key_file):
            try:
                self.__delete_file(key_file)
            except Exception as err:
                raise Exception('Unable to delete private key: {e}'.format(e=err))
        if os.path.isfile(req_file):
            try:
                self.__delete_file(req_file)
            except Exception as err:
                raise Exception('Unable to delete certificate request: {e}'.format(e=err))
        if os.path.isfile(crt_file):
            try:
                self.__delete_file(crt_file)
            except Exception as err:
                raise Exception('Unable to delete certificate: {e}'.format(e=err))
        if os.path.isfile(pem_file):
            try:
                self.__delete_file(pem_file)
            except Exception as err:
                raise Exception('Unable to delete pem certificate: {e}'.format(e=err))
        if os.path.isfile(p12_file):
            try:
                self.__delete_file(p12_file)
            except Exception as err:
                raise Exception('Unable to delete p12 certificate: {e}'.format(e=err))

        self._output('Node {n} ({p}) deleted.'.format(n=name, p=profile))

        return True

    def __delete_file(self, filename):
        if not os.path.isfile(filename):
            return False

        try:
            # Remove file lock
            os.chmod(filename, 0o600)
        except Exception as err:
            raise Exception('Unable to protect file: {e}'.format(e=err))

        try:
            os.unlink(filename)
        except Exception as err:
            raise Exception('Unable to delete file: {e}'.format(e=err))
