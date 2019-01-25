class Handler(object):
    descr = 'Configuration schema'
    dn = 'CN=Schema,CN=Configuration'

    def __init__(self):
        rev_dn = '/'.join(reversed(self.dn.split(',')))
        self.bind_to = '/' + rev_dn
