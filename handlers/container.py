import logging
from handlers import Handler

log = logging.getLogger(__name__)

class Impl(Handler):
    objCat = 'CN=Container'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)

    def create(self, dn, objCat):
        log.debug('create container as %s (%s)' % (dn, objCat))
        oc = '%s,%s' % (self.objCat, self.ldap.schemaDN)
        name = dn.split(',')[0].split('=')[1]
        attrs = [
            ('objectCategory', oc.encode()),
            ('objectClass', [b'top', b'container'])
        ]
        self.ldap.l.add_s(dn, attrs)
