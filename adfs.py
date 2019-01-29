#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, io, sys, stat, errno, signal, logging, pyfuse3, trio
import stat
from time import time
import sqlite3
from argparse import ArgumentParser
from adldap import AD
import ldif
import ldap.modlist as modlist

import bindings
from bindings import domain, configuration, schema

try:
    import faulthandler
except ImportError:
    pass
else:
    faulthandler.enable()


#trio_SIGINT_handler = signal.getsignal(signal.SIGINT)
#def keyboardInterruptHandler(signo, frame):
#    print("KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signo))
#    trio_SIGINT_handler(signo, frame)
#    exit(0)

#signal.signal(signal.SIGINT, keyboardInterruptHandler)
log = logging.getLogger(__name__)

def r2dn(r):
    return ','.join(['DC=%s' % x for x in r.lower().split('.')])


class ADfs(pyfuse3.Operations):
    bindings = {'/': bindings.domain,
                'CN=Configuration': bindings.configuration,
                'CN=Configuration,CN=Schema': bindings.schema
    }
    handlers = {}
#    bindings = {'/': bindings.domain,
#                'CN=Configuration': bindings.configuration,
#                'CN=Schema,CN=Configuration': bindings.schema
#    }

#    bindings = {'sysvol' : None,
#                'configuration': None,
#                'schema': None,
#                'domain': None
#    }

    def __init__(self):
        super(ADfs, self).__init__()
        self.realm = 'domain.alt'
        self.ad = AD(self.realm)
        self.realmDN = r2dn(self.realm)
        self.schemaDN = 'CN=Schema,CN=Configuration,%s' % self.realmDN
        self.cwd = r2dn(self.realm)

        #init sqlite
        self.db = sqlite3.connect(':memory:')
        self.db.text_factory = str
        self.db.row_factory = sqlite3.Row
        self.cursor = self.db.cursor()
        self.init_tables()
        self.init_handlers()
        # init bindings
#        for mp, b in self.bindings.items():
#            log.debug('initialize binding: %s -> %s' % (mp, b.__name__))
#            h = b.Handler()
#            inode = self.bind(mp, h)
#            self.handlers[inode] = h
#            log.debug('%s initialized for %s' % (h.descr, mp))
#        self.init_bindings()

#        self.update_binding('domain')
#        self.update_binding('configuration')
#        self.update_binding('schema')
#        for k,v in self.bindings.items():
#            self.update_binding(k)

    def init_handlers(self):
        import pkgutil
        import handlers
        package = handlers
        prefix = package.__name__ + "."
        for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix):
            if ispkg:
                log.debug("skipping pakcage %s" % modname)
                continue

            log.debug("load handler %s" % modname)
            m = __import__(modname, fromlist="dummy")
            h = m.Impl(self.ad)
            self.handlers[h.objCat] = h


    def bind(self, mountpoint, handler):
        log.debug('bind: %s' %mountpoint)
        if mountpoint == '/' or mountpoint == b'/':
            p_inode = pyfuse3.ROOT_INODE
            return p_inode
        else:
            p_inode = self.get_parent_inode(mountpoint)

        attrs = self.mkpath(handler.bind_to)
        log.debug('bind %s to %s' % (mountpoint, self.get_inode_name(p_inode)))
        return attrs.st_ino


    def get_handler(self, objCat):
        try:
            return self.handlers[objCat]
        except KeyError:
            return self.handlers['CN=Container']


    def refresh_inode(self, inode):
        r = self.get_row('SELECT dn, objCat FROM inodes WHERE id=?', (inode,))
        dn = r['dn'].decode('utf-8')
        log.debug('************ objCat: %s' % r['objCat'])
        objCat = self.ad.get_node_category(dn).decode('utf-8').split(',')[:1][0]

        log.debug('objCat: %s' % objCat)
#        try:
#        except:
#            objCat = r['objCat'].decode('utf-8')
#            log.debug('refresh objCat %s not found: %s' % (dn, objCat))
#        else:
#            log.debug('refresh objCat %s from LDAP: %s' % (dn, objCat))
#            self.db.execute('UPDATE inodes SET objCat=? WHERE id=?', (objCat,inode))

        log.debug('refreshing %s, dn=%s, objCat=%s' % (self.get_inode_name(inode), dn, objCat))
        h = self.get_handler(objCat)
        if not (r['objCat'] == 'DELETED'):
            for k,v in h.nodes.items():
                path = self.get_inode_path(inode)
                log.debug('update %s in %s' % (k, path))
                try:
                    sn_inode = self.get_inode('%s/%s' % (path, k))
                except NoSuchRowError:
                    log.debug('%s not exists in %s. creating...' % (k,path))
                    attrs = self.mknode(k, v.mode, inode, dn, objCat)
                    sn_inode = attrs.st_ino


                data = v.read(dn, '%s,%s' % (objCat, self.schemaDN))
                self.set_inode_data(sn_inode, data)

        ldap_nodes = self.ad.get_childs(dn)
        for n in ldap_nodes:
            log.debug('refresh %s from LDAP' % n)
            objCat = self.ad.get_node_category(n).decode('utf-8')[:-len(self.schemaDN)-1]
            sn = '%s (%s)' % (n[:-len(dn)-1], objCat[3:])
            path = '%s/%s' % (self.get_inode_path(inode), sn)
            if not self.is_exists(path):
                log.debug('creating %s' % path)
                self.mknode(sn, stat.S_IFDIR | 0o755, inode, n.encode(), self.get_objcat(n).encode())


    def set_inode_data(self, inode, data):
        d = data.encode()
        size = len(d)
        self.db.execute("UPDATE inodes SET data=?,size=? WHERE id=?", (d, size, inode))
        return size


    def get_parent_inode(self, path):
        p_path = '/'.join(path.split('/')[:-1])
        p_path = '/' if p_path == '' else p_path
        return self.get_inode(p_path)


    def update_binding(self, name):
        inode = self.bindings[name].inode
        log.debug("update %s (inode %s)" % (name, inode))
        self.update_inode(inode, True, False)
#        self.update_inode(inode, False, False)

    def get_inode_path(self, inode):
        path = []
        pinode = inode
        while pinode != pyfuse3.ROOT_INODE:
            name = self.get_inode_name(pinode)
            path.append(name.decode("utf-8"))
            log.debug("adding %s to a path" % name)
            pinode = self.get_row("SELECT parent_inode FROM contents WHERE inode=?", (pinode,))['parent_inode']

        return ('/' + '/'.join(reversed(path)))

    def path2dn(self, path):
        path = self.normpath(path)
        if path == '/' or path == b'/':
            return r2dn(self.realm)

        path = '/'.join([ x.split('(')[0].strip() for x in path.split('/')])
        log.debug('path2dn: %s' % path)
        p = ','.join(reversed(path.split('/')[1:]))
        res = p + ',' + r2dn(self.realm)
        log.debug('path2dn (res): %s' % res)
        return res

    def init_bindings(self):
        import importlib
        for k, v in self.bindings.items():
            log.debug("load binding: %s" % k)
            try:
                mod = importlib.import_module('bindings.%s' % k)
            except Exception as e:
                raise NotImplementedError('binding %s not found. %s' % (k,e))

            impl = mod.Handler()
            log.debug("bind_to: %s" % impl.bind_to)
            if impl.bind_to == '/':
                log.debug("%s is root node" % k)
                setattr(impl, 'inode', pyfuse3.ROOT_INODE)
            else:
                attrs = self.mkpath(impl.bind_to)
                setattr(impl, 'inode', attrs.st_ino)

            self.bindings[k] = impl


    def init_tables(self):
        self.cursor.execute("""
        CREATE TABLE inodes (
          id             INTEGER PRIMARY KEY,
          uid            INT NOT NULL,
          gid            INT NOT NULL,
          mode           INT NOT NULL,
          mtime_ns       INT NOT NULL,
          atime_ns       INT NOT NULL,
          ctime_ns       INT NOT NULL,
          target         BLOB(256),
          size           INT NOT NULL DEFAULT 0,
          rdev           INT NOT NULL DEFAULT 0,
          data           BLOB,
          dn             BLOB,
          objCat         BLOB(256)
        )""")

        self.cursor.execute("""
        CREATE TABLE contents (
          rowid          INTEGER PRIMARY KEY AUTOINCREMENT,
          name           BLOB(256) NOT NULL,
          inode          INT NOT NULL REFERENCES inodes(id),
          parent_inode   INT NOT NULL REFERENCES inodes(id),

          UNIQUE (name, parent_inode)
        )""")

        # insert root dir
        dn = r2dn(self.realm)
        objCat = self.get_objcat(dn)
        log.debug("create root %s of %s" % (dn, objCat))
        now_ns = int(time() * 1e9)
        self.cursor.execute("INSERT INTO inodes (id,mode,uid,gid,mtime_ns,atime_ns,ctime_ns,dn,objCat) "
                            "VALUES (?,?,?,?,?,?,?,?,?) ",
                            (pyfuse3.ROOT_INODE, stat.S_IFDIR | 0o755,
                             os.getuid(), os.getgid(), now_ns, now_ns, now_ns, dn.encode(), objCat.encode()))

        self.cursor.execute("INSERT INTO contents (name, parent_inode, inode) VALUES(?,?,?)",
                            (b'..', pyfuse3.ROOT_INODE, pyfuse3.ROOT_INODE))


    def get_objcat(self, dn):
        objCat = self.ad.get_attrs(dn, ['objectCategory'])['objectCategory'][0]
        return objCat.decode('utf-8')[:-len('CN=Schema,CN=Configuration,%s' % r2dn(self.realm))-1]


    def get_row(self, *a, **kw):
        self.cursor.execute(*a, **kw)
        try:
            row = next(self.cursor)
        except StopIteration:
            raise NoSuchRowError()
        try:
            next(self.cursor)
        except StopIteration:
            pass
        else:
            raise NoQniqueValueError()

        return row


    def getattr_sync(self, inode, ctx=None):
        try:
            row = self.get_row("SELECT * FROM inodes WHERE id=?", (inode,))
        except NoSuchRowError:
            raise(pyfuse3.FUSEError(errno.ENOENT))

        entry = pyfuse3.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300

        entry.st_mode = row['mode']
        entry.st_nlink = self.get_row("SELECT COUNT(inode) FROM contents WHERE inode=?", (inode,))[0]
        entry.st_uid = row['uid']
        entry.st_gid = row['gid']
        entry.st_rdev = row['rdev']
        entry.st_size = row['size']

        entry.st_blksize = 512
        entry.st_blocks = 1
        entry.st_atime_ns = row['atime_ns']
        entry.st_mtime_ns = row['mtime_ns']
        entry.st_ctime_ns = row['ctime_ns']

        return entry


    async def getattr(self, inode, ctx=None):
        return self.getattr_sync(inode, ctx)


    async def lookup(self, inode_p, name, ctx=None):
        log.debug('lookup for %s in %s' % (name, self.get_inode_path(inode_p)))
        self.refresh_inode(inode_p)
        if name == '.':
            inode = inode_p
        elif name == '..':
            inode = self.get_row("SELECT * FROM contents WHERE inode=?", (inode_p,))['parent_inode']
        else:
            try:
                inode = self.get_row("SELECT * FROM contents WHERE name=? AND parent_inode=?", (name, inode_p))['inode']
            except NoSuchRowError:
                raise(pyfuse3.FUSEError(errno.ENOENT))

        return await self.getattr(inode, ctx)


    async def readlink(self, inode, ctx):
        return self.get_row("SELECT * FROM inodes WHERE id=?", (inode,))['target']


    async def opendir(self, inode, ctx):
        self.refresh_inode(inode)
        return inode


    async def readdir(self, inode, off, token):
        if off == 0:
            off = -1

        cursor2 = self.db.cursor()
        cursor2.execute("SELECT * FROM contents WHERE parent_inode=? AND rowid > ? ORDER BY rowid", (inode,off))
        for row in cursor2:
            pyfuse3.readdir_reply(token, row['name'], await self.getattr(row['inode']), row['rowid'])


    async def open(self, inode, flags, ctx):
        log.debug('open %s' % inode)
        return inode


    async def read(self, fh, off, length):
        log.debug('open %s file (off, length) (%s, %s)' % (fh, off, length))
        data = self.get_row('SELECT data FROM inodes WHERE id=?', (fh,))[0]
        if data is None:
            return b''

#        log.debug('data is: %s' % data)
        return data[off:off+length]


    def _create(self, inode_p, name, mode, ctx=None, rdev=0, target=None):
        log.debug("creating %s" % name)
        if not ctx:
            ctx = lambda: None
            ctx.uid = os.getuid()
            ctx.gid = os.getgid()

        if (self.getattr_sync(inode_p)).st_nlink == 0:
            log.warn('Attempted to create entry %s with unlinked parent %d',
                     name, inode_p)
            raise FUSEError(errno.EINVAL)

        now_ns = int(time() * 1e9)
        self.cursor.execute('INSERT INTO inodes (uid, gid, mode, mtime_ns, atime_ns, '
                            'ctime_ns, target, rdev) VALUES(?, ?, ?, ?, ?, ?, ?, ?)',
                            (ctx.uid, ctx.gid, mode, now_ns, now_ns, now_ns, target, rdev))

        inode = self.cursor.lastrowid
        self.db.execute("INSERT INTO contents(name, inode, parent_inode) VALUES(?,?,?)",
                        (name, inode, inode_p))
        log.debug("%s created" % name)
        return self.getattr_sync(inode)


    async def mkdir(self, inode_p, name, mode, ctx):
        name = name.decode('utf-8')
        nodeName = name.split('(')[0].strip()
        objCat = name.split('(')[1].rstrip(')')

        dn = '%s,%s' % (nodeName, self.path2dn(self.get_inode_path(inode_p)))

        attrs = self.mknode(name, stat.S_IFDIR | 0o755, inode_p, dn.encode(), objCat.encode())
        h = self.handlers['CN=%s' % objCat]
        h.create(dn, objCat)
#        self.ad.mknode(dn, nodeName.split('=')[1], '%s,%s' % (objCat, self.schemaDN))
        return attrs


    async def write(self, fh, offset, buf):
        log.debug("write (fh, offset, buf) (%s, %s, %s)" % (fh, offset, buf))
        res = self.get_row('SELECT data, objCat FROM inodes WHERE id=?', (fh,))
        data_old = res['data']
        objCat = res['objCat']
        log.debug("old len: %s" % len(data_old))
        log.debug("buf len: %s" % len(buf))
        if data_old is None:
            data_new = b''

        # TODO: check that we replace whole data_old but not edit by chunks
        data_new = buf
#        data_new = data_old[:offset] + buf + data_old[offset+len(buf):]
        log.debug("data_new: %s" % data_new)

        h = self.get_handler(objCat)
        path = self.get_inode_path(fh)
        name = self.get_inode_name(fh)
        dn = self.path2dn(path)[len(name)+1:]
        h.write(name, dn, data_old, buf)
        p_inode = self.get_parent_inode(path)
        self.refresh_inode(p_inode)
        return len(buf)


    async def unlink(self, inode_p, name,ctx):
        log.debug('unlink: %s (parent %s)' % (name, self.get_inode_path(inode_p)))
        entry = await self.lookup(inode_p, name)

        if stat.S_ISDIR(entry.st_mode):
            raise pyfuse3.FUSEError(errno.EISDIR)

        self._remove(inode_p, name, entry)


    async def rmdir(self, inode_p, name, ctx):
        log.debug("rmdir for %s" % name)
        entry = await self.lookup(inode_p, name)

        if not stat.S_ISDIR(entry.st_mode):
            raise pyfuse3.FUSEError(errno.ENOTDIR)

        self._remove(inode_p, name, entry)


    def _remove(self, inode_p, name, entry):
        if self.get_row("SELECT COUNT(inode) FROM contents WHERE parent_inode=?",
                        (entry.st_ino,))[0] > 0:
            raise pyfuse3.FUSEError(errno.ENOTEMPTY)

        if stat.S_ISDIR(entry.st_mode ):
            dn = self.path2dn(self.get_inode_path(entry.st_ino))
            self.ad.delete_node(dn)

        self.cursor.execute("DELETE FROM contents WHERE name=? AND parent_inode=?",
                            (name, inode_p))

        self.cursor.execute("DELETE FROM inodes WHERE id=?", (entry.st_ino,))
        log.debug("SET objCat as DELETED for inode %s" % inode_p)
        self.cursor.execute("UPDATE inodes SET objCat=? WHERE id=?", ('DELETED', inode_p))
#        if entry.st_nlink == 1 and entry.st_ino not in self.inode_open_count:
#            self.cursor.execute("DELETE FROM inodes WHERE id=?", (entry.st_ino,))


    async def rename(self, inode_p_old, name_old, inode_p_new, name_new,
                     flags, ctx):
        if flags != 0:
            raise FUSEError(errno.EINVAL)

        entry_old = await self.lookup(inode_p_old, name_old)

        try:
            entry_new = await self.lookup(inode_p_new, name_new)
        except pyfuse3.FUSEError as exc:
            if exc.errno != errno.ENOENT:
                raise
            target_exists = False
        else:
            target_exists = True

        if target_exists:
            # replace is not implemented yet
            self._replace(inode_p_old, name_old, inode_p_new, name_new,
                          entry_old, entry_new)
        else:
            new_path = self.get_inode_path(inode_p_new)
            new_dn = self.path2dn(new_path)
            old_path = self.get_inode_path(entry_old.st_ino)
            old_dn = self.path2dn(old_path)
            self.ad.move(old_dn, name_new.decode('utf-8'), new_dn)
            self.cursor.execute("UPDATE contents SET name=?, parent_inode=? WHERE name=? "
                                "AND parent_inode=?", (name_new, inode_p_new,
                                                       name_old, inode_p_old))


    def normpath(self, path):
        path = '/' + path.lstrip('/')
        log.debug('%s -> %s' % (path, os.path.normpath(path)))
        return os.path.normpath(path)


    def get_inode(self, path):
        path = self.normpath(path)
        log.debug('get_inode: %s' % path)
        p_inode = pyfuse3.ROOT_INODE
        if path == '/':
            return p_inode

        log.debug("search inode for %s" % (path,))
        for p in path.split('/')[1:]:
            log.debug('part: %s, p_inode: %s' % (p, p_inode))
            p_inode = self.get_row("SELECT inode FROM contents WHERE name=? AND parent_inode=?", (p.encode(), p_inode))['inode']

        return p_inode


    def get_inode_name(self, inode):
        if inode == pyfuse3.ROOT_INODE:
            return '/'

        return self.get_row("SELECT name FROM contents WHERE inode=?", (inode,))['name']


    def is_exists(self, path):
        path = self.normpath(path)
        log.debug("[is_exists] %s" % (path))
        if path == '/': # root must exists
            return True

        p_inode = pyfuse3.ROOT_INODE
        for p in path.split('/')[1:]:
            if self.get_inode_name(p_inode) == b'..':
                continue

            log.debug("[is_exists] search for %s in %s" % (p, self.get_inode_name(p_inode)))
            try:
                p_inode = self.get_row("SELECT inode FROM contents WHERE name=? AND parent_inode=?", (p.encode(), p_inode))['inode']
            except NoSuchRowError:
                return False

        return True


    def is_dir(self, path):
        path = self.normpath(path)
        if path == '/':
            return True

        log.debug('check is_dir for %s' % path)
        inode = self.get_inode(path)
        mode = self.get_row("SELECT mode FROM inodes WHERE id=?", (inode,))['mode']
        return (stat.S_ISDIR(mode))


    def is_contains(self, path, name):
        path = self.normpath(path)
        try:
            self.get_inode('/'.join([path, name]))
        except NoSuchRowError:
            return False

        return True


    def _check_mk_validity(self, path, name):
        path = self.normpath(path)
        log.debug('check validity for %s' % path)
        if not self.is_exists(path):
            raise pyfuse3.FUSEError(errno.ENOENT)

        if not self.is_dir(path):
            raise pyfuse3.FUSEError(errno.ENOTDIR)

        if self.is_contains(path, name):
            raise pyfuse3.FUSEError(errno.EEXIST)


    def _vcreate(self, path, name, mode):
        path = self.normpath(path)
        inode = self.get_inode(path)
        if not inode:
            log.error("inode for %s not found" % (path))

        log.debug("inode for %s is %s" % (path, inode))
        return self._create(inode, name.encode(), mode)


    def mkvdir(self, path, name):
        log.debug("creating vdir %s in %s" % (name, path))
        self._check_mk_validity(path, name)
        return self._vcreate(path, name, stat.S_IFDIR | 0o755)


    def mkvfile(self, path, name):
        log.debug("creating vfile %s in %s" % (name, path))
        self._check_mk_validity(path, name)
        return self._vcreate(path, name, stat.S_IFREG | 0o644)


    def mknode(self, name, mode, p_inode, dn, objCat):
        now_ns = int(time() * 1e9)
        self.cursor.execute("INSERT INTO inodes (mode,uid,gid,mtime_ns,atime_ns,ctime_ns,dn,objCat) "
                            "VALUES (?,?,?,?,?,?,?,?) ",
                            (mode, os.getuid(), os.getgid(), now_ns, now_ns, now_ns, dn, objCat))

        inode = self.cursor.lastrowid
        self.cursor.execute("INSERT INTO contents (name, parent_inode, inode) VALUES(?,?,?)",
                            (name.encode(), p_inode, inode))

        return self.getattr_sync(inode)


    def mkpath(self, path):
        path = self.normpath(path)
        if path == '/':
            return self.getattr_sync(pyfuse3.ROOT_INODE)

        dirs = path.split('/')[1:-1]
        ppath = '/'
        for d in dirs:
            if ppath == '/':
                continue

            try:
                self._check_mk_validity(ppath, d)
            except pyfuse3.FUSEError(errno.EEXIST):
                pass
            else:
                self._vcreate(ppath, d, stat.S_IFDIR | 0o755)
            ppath = ppath + '/' + d


        last_node = '/'.join(path.split('/')[-1:])
        ppath = '/'.join(path.split('/')[:-1])
        self._check_mk_validity(ppath, last_node)
        return self._vcreate(ppath, last_node, stat.S_IFDIR | 0o755)


    def res2ldif(self, dn, res):
        data = io.StringIO()
        lwr = ldif.LDIFWriter(data, cols=80)
        lwr.unparse(dn, dict(res))
        data = data.getvalue()
        return data

def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)

def parse_args():
    '''Parse command line'''

    parser = ArgumentParser()

    parser.add_argument('mountpoint', type=str,
                        help='Where to mount the file system')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debugging output')
    parser.add_argument('--debug-fuse', action='store_true', default=False,
                        help='Enable FUSE debugging output')
    return parser.parse_args()


class NoUniqueValueError(Exception):
    def __str__(self):
        return 'Query generated more than 1 result row'


class NoSuchRowError(Exception):
    def __str__(self):
        return 'Query produced 0 result rows'

def main():
    options = parse_args()
    init_logging(options.debug)

    testfs = ADfs()
    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('fsname=ad')
    if options.debug_fuse:
        fuse_options.add('debug')
    pyfuse3.init(testfs, options.mountpoint, fuse_options)
    try:
        trio.run(pyfuse3.main)
    except:
        pyfuse3.close(unmount=False)
        raise

    pyfuse3.close()


if __name__ == '__main__':
    main()
