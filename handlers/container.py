from handlers import Handler

class Impl(Handler):
    objCat = 'CN=Container'

    def __init__(self, ldap):
        super(Impl, self).__init__(ldap)
#        self.__name__ = 'Domain'
