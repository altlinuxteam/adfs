from handlers import Handler

class Impl(Handler):
    objCat = 'default'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)

    def attributes(self):
        return '.attributes'

    def schema(self):
        return '.schema'
