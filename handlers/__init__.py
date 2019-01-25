import io, stat, logging
log = logging.getLogger(__name__)


class VNode(object):
    ldif_cols = 255
    def __init__(self, binding, mode, ldap, ldap_attrs):
        self.mode = mode
        self.ldap = ldap
        self.attrs = ldap_attrs
        self.binding = binding

    def get_dn(self, dn, objCat):
        if self.binding == 'base':
            return dn
        elif self.binding == 'schema':
            return objCat

    def data_from_raw(self, dn, raw):
        return self._raw2ldif(dn, raw)

    def _raw2ldif(self, dn, raw):
        import ldif
        data = io.StringIO()
        lwr = ldif.LDIFWriter(data, cols=self.ldif_cols)
        lwr.unparse(dn, dict(raw))
        data = data.getvalue()
        return data

    def read(self, dn, objCat):
        return self._read(dn, objCat)

    def _read(self, dn, objCat):
        log.debug('_read with %s (%s)' % (dn, objCat))
        _dn = self.get_dn(dn, objCat)
        raw_data = self.ldap.get_attrs(_dn, self.attrs)
#        log.debug('_read: %s' % raw_data)
        return self._raw2ldif(dn, raw_data)


class Handler(object):
    nodes = {}

    def __init__(self, ldap):
        self.nodes = {'.attributes': VNode('base', stat.S_IFREG | 0o644, ldap, ['*']),
                     '.schema': VNode('schema', stat.S_IFREG | 0o444, ldap, ['*']),
        }
        self._mods = {'dummy': self.__dummy__}


    def __dummy__(self):
        return None

#    def fqsdn(self):
#        return '%s,%s' % (self.objCat, self.schema_dn)
