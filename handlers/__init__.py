import io, stat, logging
import ldif
import ldap.modlist as modlist

log = logging.getLogger(__name__)

class VNode(object):
    ldif_cols = 255
    deleted = False
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

    def write(self, *args, **kwargs):
        return None


class Schema(VNode):
    def __init__(self, ldap):
        self.mode = stat.S_IFREG | 0o644
        self.ldap = ldap
        self.attrs = ['*']
        super(Schema, self).__init__('schema', self.mode, self.ldap, self.attrs)


class Attrs(VNode):
    def __init__(self, ldap):
        self.mode = stat.S_IFREG | 0o644
        self.ldap = ldap
        self.attrs = ['*']
        super(Attrs, self).__init__('base', self.mode, self.ldap, self.attrs)

    def write(self, dn, old_data, new_data):
        log.debug('write DN: %s' % dn)
        old_dict = ldif.LDIFRecordList(io.StringIO(old_data.decode('utf-8')))
        old_dict.parse()
        log.debug("dict_old: %s" % old_dict.all_records)
        new_dict = ldif.LDIFRecordList(io.StringIO(new_data.decode('utf-8')))
        new_dict.parse()
        log.debug("dict_new: %s" % new_dict.all_records)
        _ldif = modlist.modifyModlist(old_dict.all_records[0][1], new_dict.all_records[0][1])
        if (1, 'objectCategory', None) in _ldif:
            (_, o) = old_dict.all_records[0]
            (_, n) = new_dict.all_records[0]
            cat_old = o['objectCategory'][0].decode('utf-8')[:-len(self.ldap.schemaDN)-1]
            cat_new = n['objectCategory'][0].decode('utf-8')[:-len(self.ldap.schemaDN)-1]
            log.debug('objectCategory changed for %s (%s -> %s)' % (dn, cat_old, cat_new))
            return cat_new

        log.debug("_ldif: %s" % _ldif)
        self.ldap.apply_diff(dn, _ldif)
        return None


class Handler(object):
    nodes = {}

    def __init__(self, ldap):
        self.nodes = {'.attributes': Attrs(ldap),
                     '.schema': Schema(ldap),
        }
        self._mods = {'dummy': self.__dummy__}
        self.ldap = ldap


    def safeDecode(self, xs):
        return map(lambda x: x.decode('utf-8') if isinstance(x, bytes) else x, xs)

    def __dummy__(self):
        return None

    def write(self, name, dn, old_data, new_data):
        [name, dn] = self.safeDecode([name, dn])
        return self.nodes[name].write(dn, old_data, new_data)
