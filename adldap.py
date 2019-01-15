#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, errno, logging
import ldap, ldap.sasl, ldap.schema
from argparse import ArgumentParser
from logging import debug, info, warning
# samba imports
import samba.param
from samba.credentials import Credentials
from samba.dcerpc import nbt
from samba.net import Net


log = logging.getLogger(__name__)

def r2dn(r):
    return ','.join(['DC=%s' % x for x in r.lower().split('.')])


class AD(object):
    def __init__(self, realm):
        self.realm = realm
        debug("initialize LDAP")
        self.__init_samba_params()
        self.__init_ldap()

    def get(self, node):
        debug("fetching node: %s" % node)
        self.get_root()


    def __init_ldap(self):
        pdc = self.finddc()
        self.l = ldap.initialize('ldap://%s' % (pdc), bytes_mode=False)
        self.l.procotol_version = 3
        self.l.set_option(ldap.OPT_X_SASL_NOCANON, True)
        auth_tokens = ldap.sasl.gssapi('')
        self.l.sasl_interactive_bind_s('', auth_tokens)
        self.l.set_option(ldap.OPT_REFERRALS,0)
        # init subschema
        sub_dn = self.l.search_subschemasubentry_s(r2dn(self.realm))
        sub_entry = self.l.read_subschemasubentry_s(sub_dn, ldap.schema.SCHEMA_ATTRS)
        self.schema =  ldap.schema.SubSchema(sub_entry)


    def get_object_classes(self, dn):
        (_, res) = self.ldap_search(dn=dn, scope=ldap.SCOPE_BASE, attrs=['objectClass'])[0]
        log.debug('get_object_classes: %s' % res)
        if not res:
            return []
        else:
            return res['objectClass']


    def get_childs(self, dn):
        res = self.ldap_search(dn=dn, scope=ldap.SCOPE_ONELEVEL, attrs=['dn'])
        if not res:
            return []
        else:
            return map(lambda x: x[0], res)

    def get_root(self):
#        (dn, res) = self.ldap_search(dn=r2dn(realm), scope=ldap.SCOPE_BASE, attrs=['*'])[0]
        res = self.ldap_search(dn=r2dn(self.realm), scope=ldap.SCOPE_ONELEVEL, attrs=['dn'])
        return map(lambda x: x[0], res)
#        res = self.ldap_search(dn=r2dn(realm), scope=ldap.SCOPE_SUBTREE, attrs=['dn'])
#        for r in res:
#            (n,_) = r
#            print(n)
#        print(res)


    def read_node(self, dn):
        res = self.ldap_search(dn, scope=ldap.SCOPE_BASE, attrs=['*'])[0][1]
        return res


    def ldap_search(self, dn=None, expr=None, scope=ldap.SCOPE_SUBTREE, attrs=[]):
        if not dn:
            dn = self.base_dn

        try:
            if not expr:
                expr = '(objectClass=*)' # fix for old ldap (should accept None)

            log.debug("ldap_search: (dn, scope, expr, attrs) (%s, %s, %s, %s)" % (dn, scope, expr, attrs))
            res = self.l.search_s(dn, scope, expr, attrs)
        except Exception as e:
            print("search %s on %s failed with %s" % (expr, dn, e))
            raise

        ret = [ (r, dn) for (r, dn) in res if r ]
        return ret if ret else None


    def finddc(self, realm=None, flags=None):
        if not realm:
            realm = self.realm

        if not flags:
            flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE

        net = Net(creds=self.creds, lp=self.lp)
        ret = net.finddc(domain=realm, flags=flags)
        return ret.pdc_dns_name


    def apply_diff(self, dn, diff):
        log.debug('applying diff: %s' % diff)
        self.l.modify_s(dn, diff)


    def __init_samba_params(self, root_use_machine_creds = True):
        lp = samba.param.LoadParm()
        try:
            lp.load_default()
        except Exception as e:
            raise RuntimeError("cannot load default samba parameters", e)

        creds = Credentials()
        creds.guess(lp)
        if os.getuid() == 0 and root_use_machine_creds: # use machine credentials
            debug('use machine account')
#            creds.set_machine_account(lp)
            self.use_machine_creds = True

        self.lp = lp
        self.realm = lp.get('realm')
        self.base_dn = r2dn(self.realm)
        self.creds = creds


def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


def parse_args():
    '''Parse command line'''

    parser = ArgumentParser()

    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debugging output')
    return parser.parse_args()

def main():
    options = parse_args()
    init_logging(options.debug)

    ad = AD("domain.alt")
    ad.get("root")

if __name__ == '__main__':
    main()
