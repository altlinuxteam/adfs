import io, stat, logging
from handlers import Handler, VNode, log
import ldif
import ldap.modlist as modlist

log = logging.getLogger(__name__)

class Create(VNode):
    def __init__(self, ldap):
        super(Create, self).__init__('base', stat.S_IFREG | 0o644, ldap, ['*'])


    def _read(self, dn, objCat):
        return '# write ldif here to create a new user'


    def create(self, dn, schemaDN):
        objCatOld = self.ldap.get_node_category(dn)
        objCat = 'CN=Person,%s' % schemaDN
        if objCatOld == objCat:
            return

        account = dn.split(',')[0].split('=')[1]
        attrs = [('objectCategory', objCat.encode()),
                 ('sAMAccountName', account.encode())
        ]
        log.debug('replace %s of %s with %s of %s' % (dn, objCatOld, dn, objCat))
        self.ldap.delete_s(dn)
        self.ldap.add_s(dn, attrs)

    def write(self, *args, **kwargs):
        return None

class Impl(Handler):
    objCat = 'CN=Person'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)
        self.nodes.update({'.create': Create(ldap)})

    def create(self, dn, objCat):
        log.debug('create user as %s (%s)' % (dn, objCat))
        oc = '%s,%s' % (self.objCat, self.ldap.schemaDN)
        name = dn.split(',')[0].split('=')[1]
        attrs = [
            ('objectCategory', oc.encode()),
            ('objectClass', [b'top', b'person', b'organizationalPerson', b'user']),
            ('sAMAccountName', name.encode())
        ]
        self.ldap.l.add_s(dn, attrs)

    def replace(self, dn):
#        attrs = ldif.LDIFRecordList(io.StringIO(buf.decode('utf-8')))
#        attrs.parse()
        log.debug('replacing %s' % dn)
        self.ldap.l.delete_s(dn)
        self.create(dn, self.objCat)
