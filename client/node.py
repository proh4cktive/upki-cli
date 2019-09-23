
# -*- coding:utf-8 -*-

class Node(object):
    def __init__(self, conf):
        self.url  = conf['url']
        self.state   = conf['state']
        self.name    = conf['name']
        self.profile = conf['profile']
        self.sans    = conf.get('sans', [])
        self.p12     = conf.get('p12', False)
        self.passwd  = conf.get('passwd', None)
