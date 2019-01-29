import stat, logging
from handlers import Handler, VNode

log = logging.getLogger(__name__)

class Impl(Handler):
    objCat = 'CN=Organizational-Unit'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)

    def create(self, dn, objCat):
        log.debug('create organizational unit as %s (%s)' % (dn, objCat))
        oc = '%s,%s' % (self.objCat, self.ldap.schemaDN)
        name = dn.split(',')[0].split('=')[1]
        attrs = [
            ('objectCategory', oc.encode()),
            ('objectClass', [b'top', b'organizationalUnit'])
        ]
        self.ldap.l.add_s(dn, attrs)
