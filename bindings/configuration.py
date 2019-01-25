class Handler(object):
    descr = 'Configuration endpoint handler'
    dn = 'CN=Configuration'
    def __init__(self):
        self.node_name = self.dn
        self.bind_to = '/' + self.dn
