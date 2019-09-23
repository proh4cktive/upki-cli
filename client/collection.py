# -*- coding:utf-8 -*-

import os
import json

class Collection(object):
    def __init__(self, path):
        self.nodes  = list()
        self.path   = path
        self.conf   = os.path.join(self.path, 'cli.nodes.json')

        # Initialize if needed
        if not os.path.isfile(self.conf):
            try:
                self.__update()
            except Exception as err:
                raise Exception('Unable to initialize collection: {e}'.format(e=err))

    def __update(self, data=[]):
        # Update file
        with open(self.conf, 'wt') as raw:
            raw.write(json.dumps(data, indent=4))

    def list_nodes(self):
        with open(self.conf, 'rt') as raw:
            self.nodes = json.loads(raw.read())

        return self.nodes

    def get_node(self, name, profile):
        for n in self.nodes:
            if (n['name'] == name) and (n['profile'] == profile):
                return n

        return None

    def load_node_keychain(self, node):
        keypath = os.path.join(self.path, '{p}.{n}.key'.format(p=node['profile'], n=node['name']))
        crtpath = os.path.join(self.path, '{p}.{n}.crt'.format(p=node['profile'], n=node['name']))
        
        with open(keypath, 'rt') as raw:
            key = raw.read()
        with open(crtpath, 'rt') as raw:
            cert = raw.read()

        return (key, cert)

    def register(self, name, profile, sans, p12=False, passwd=None):
        node = dict({'state': 'init','name': name, 'profile': profile, 'sans': sans, 'p12': p12, 'passwd': passwd})

        for n in self.nodes:
            if (n['name'] == node['name']) and (n['profile'] == node['profile']):
                raise Exception('This node already exists')

        # Append node to list
        self.nodes.append(node)

        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception('Unable to register node: {e}'.format(e=err))

    def sign(self, name, profile):
        for i, n in enumerate(self.nodes):
            if (n['name'] == name) and (n['profile'] == profile):
                self.nodes[i]['state'] = 'signed'
                break

        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception('Unable to register node: {e}'.format(e=err))

    def remove(self, name, profile):
        for i, n in enumerate(self.nodes):
            if (n['name'] == name) and (n['profile'] == profile):
                del self.nodes[i]
                break
        
        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception('Unable to remove node: {e}'.format(e=err))

    def __renew_node(self, node):
        try:
            (key, cert) = self.__load_keychain(node)
        except Exception as err:
            raise Exception('Unable to load node {n} ({p}) keychain: {e}'.format(n=node['name'], p=node['profile'], e=err))

        if rep.status_code != 200:
            raise Exception('HTTP Error on renew request: {}'.format(rep.status_code))

        try:
            data = rep.json()
        except ValueError as err:
            try:
                error = rep.text
                raise Exception(error)
            except AttributeError:
                raise Exception('Unable to parse JSON answer; {e}'.format(e=err))

        if data.get('status') != 'success':
            raise Exception(data.get('message'))

        try:
            data['certificate']
        except KeyError:
            raise Exception('Missing certificate')

        