import stat
from handlers import Handler, VNode

class Create(VNode):
    def __init__(self, ldap):
        super(Create, self).__init__('base', stat.S_IFREG | 0o644, ldap, ['*'])


    def _read(self, dn, objCat):
        return '# write ldif here to create a new user'

class Impl(Handler):
    objCat = 'CN=Person'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)
        self.nodes.update({'.create': Create(ldap)})
