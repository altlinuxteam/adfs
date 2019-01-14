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

def_dir_mode = stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH

def r2dn(r):
    return ','.join(['DC=%s' % x for x in r.lower().split('.')])

class ADfs(pyfuse3.Operations):
    def path2dn(self, path):
        return (self.realm)


    def __init__(self):
        super(ADfs, self).__init__()
        self.realm = 'domain.alt'
        self.ad = AD(self.realm)
        self.cwd = r2dn(self.realm)

        #init sqlite
        self.db = sqlite3.connect(':memory:')
        self.db.text_factory = str
        self.db.row_factory = sqlite3.Row
        self.cursor = self.db.cursor()
        self.init_tables()
        self.update_node('/')


    def _update_root(self):
        nodes = self.ad.get_childs(r2dn(self.realm))
        for _n in nodes:
            dn = str.encode(_n)[:-len(r2dn(self.realm))-1] # DN without realm's DN
            cursor2 = self.db.cursor()
            inode = cursor2.execute("SELECT inode FROM contents WHERE name=?", (dn,)).fetchone()
            if inode: # node already exists
                log.debug("skip inode: %s" % inode)
                break
            else:
                log.debug("add %s to /" % dn)
                now_ns = int(time() * 1e9)
                self.cursor.execute("INSERT INTO inodes (uid, gid, mode, mtime_ns, atime_ns, ctime_ns, target, rdev) "
                                    "VALUES (?,?,?,?,?,?,?,?)",
                                    (os.getuid(), os.getgid(), stat.S_IFDIR | 0o755, now_ns, now_ns, now_ns, None, 0))
                inode = self.cursor.lastrowid
                self.db.execute("INSERT INTO contents (name, inode, parent_inode) VALUES (?,?,?)", (dn, inode, pyfuse3.ROOT_INODE))


    def get_inode_name(self, inode):
        return self.get_row("SELECT name FROM contents WHERE inode=?", (inode,))['name']


    def get_inode_path(self, inode):
        path = []
        pinode = inode
        while pinode != pyfuse3.ROOT_INODE:
            name = self.get_inode_name(pinode)
            path.append(name.decode("utf-8"))
            log.debug("adding %s to a path" % name)
            pinode = self.get_row("SELECT parent_inode FROM contents WHERE inode=?", (pinode,))['parent_inode']

        return ('/' + '/'.join(path))
#        return ('/' + '/'.join(reversed(path)))


    def path2dn(self, path):
        log.debug('path2dn: %s' % path)
        p = ','.join(path.split('/')[1:])
        res = p + ',' + r2dn(self.realm)
        log.debug('path2dn (res): %s' % res)
        return res


    def update_node(self, node):
        if node == '/': # update root (realm) node
            self._update_root()


    def update_inode(self, inode):
        if inode == pyfuse3.ROOT_INODE:
            self._update_root()
            return

        # try to get children from cache
        childs = self.db.execute("SELECT * FROM contents WHERE parent_inode=?", (inode,)).fetchone()
        if not childs: # update cache from AD
            cwd = self.get_inode_path(inode)
            log.debug('cwd: %s' % cwd)
            pdn = self.path2dn(cwd) # parent dn
            log.debug('pdn: %s' % pdn)
            dns = self.ad.get_childs(pdn)
            now_ns = int(time() * 1e9)

            # insert attributes file
            log.debug("add attributes to %s" % pdn)
            name = b'.attributes'
            cursor2 = self.db.cursor()
            cursor2.execute("INSERT INTO inodes (uid, gid, mode, mtime_ns, atime_ns, ctime_ns, target, rdev) "
                            "VALUES (?,?,?,?,?,?,?,?)",
                            (os.getuid(), os.getgid(), stat.S_IFREG | 0o644, now_ns, now_ns, now_ns, None, 0))
            attrs_inode = cursor2.lastrowid
            log.debug("insert new record: (name, inode, parent_inode) (%s, %s, %s)" % (name, attrs_inode, inode))
            self.db.execute("INSERT INTO contents (name, inode, parent_inode) VALUES (?,?,?)", (name, attrs_inode, inode))
            data_len = self.update_inode_data(attrs_inode)
            self.db.execute("UPDATE inodes SET size=? WHERE id=?", (data_len, attrs_inode))


            for dn in dns: # insert node to the cache
                log.debug("add %s to %s" % (pdn, dn))
                name = str.encode(dn)[:-len(pdn)-1]
                self.cursor.execute("INSERT INTO inodes (uid, gid, mode, mtime_ns, atime_ns, ctime_ns, target, rdev) "
                                    "VALUES (?,?,?,?,?,?,?,?)",
                                    (os.getuid(), os.getgid(), stat.S_IFDIR | 0o755, now_ns, now_ns, now_ns, None, 0))
                c_inode = self.cursor.lastrowid
                log.debug("insert new record: (name, inode, parent_inode) (%s, %s, %s)" % (name, c_inode, inode))
                self.db.execute("INSERT INTO contents (name, inode, parent_inode) VALUES (?,?,?)", (name, c_inode, inode))
        else:
            log.debug("skip updating %s" % self.get_inode_name(inode))


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
          data           BLOB
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
        now_ns = int(time() * 1e9)
        self.cursor.execute("INSERT INTO inodes (id,mode,uid,gid,mtime_ns,atime_ns,ctime_ns) "
                            "VALUES (?,?,?,?,?,?,?) ",
                            (pyfuse3.ROOT_INODE, stat.S_IFDIR |
                             stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                             stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                             stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH ,
                             os.getuid(), os.getgid(), now_ns, now_ns, now_ns))

        self.cursor.execute("INSERT INTO contents (name, parent_inode, inode) VALUES(?,?,?)",
                            (b'..', pyfuse3.ROOT_INODE, pyfuse3.ROOT_INODE))

        self.cursor.execute("INSERT INTO inodes (mode,uid,gid,mtime_ns,atime_ns,ctime_ns) "
                            "VALUES (?,?,?,?,?,?) ",
                            (stat.S_IFDIR | 0o755,
                             os.getuid(), os.getgid(), now_ns, now_ns, now_ns))
        cid = self.cursor.lastrowid
        self.cursor.execute("INSERT INTO contents (name, parent_inode, inode) VALUES(?,?,?)",
                            (b'CN=Configuration', pyfuse3.ROOT_INODE, cid))


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


    async def getattr(self, inode, ctx=None):
        row = self.get_row("SELECT * FROM inodes WHERE id=?", (inode,))

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

    async def lookup(self, inode_p, name, ctx=None):
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
        return inode


    async def readdir(self, inode, off, token):
        if off == 0:
            off = -1

        self.update_inode(inode)
        cursor2 = self.db.cursor()
        cursor2.execute("SELECT * FROM contents WHERE parent_inode=? AND rowid > ? ORDER BY rowid", (inode,off))
        for row in cursor2:
            pyfuse3.readdir_reply(token, row['name'], await self.getattr(row['inode']), row['rowid'])


    async def open(self, inode, flags, ctx):
        log.debug('open %s' % inode)
        return inode


    def get_inode_dn(self, inode):
        iname = self.get_inode_name(inode)
        log.debug('iname: %s' % iname)
        if iname == b'.attributes':
            return self.path2dn(self.get_inode_path(inode))[len('.attributes')+1:]
        else:
            return self.path2dn(self.get_inode_path(inode))


    def update_inode_data(self, inode):
        name = self.get_inode_name(inode)
        data = None
        log.debug('updating %s (%s)' % (name, inode))
        if name == b'.attributes':
            dn = self.path2dn(self.get_inode_path(inode))[len(name)+1:]
            data = self.ad.read_node(dn)
        if data:
            data_bytes = str(data).encode()
#            log.debug('data_bytes: %s' % data_bytes.decode('utf-8'))
            node_dn = self.get_inode_dn(inode)
            data_ldif = io.StringIO()
            lwr = ldif.LDIFWriter(data_ldif)
            lwr.unparse(node_dn, dict(data))
#            ldif.CreateLDIF(node_dn, dict(data))
            data_out = ('# DN: %s\n%s' % (node_dn, data_ldif.getvalue())).encode()
            self.db.execute("UPDATE inodes SET data=? WHERE id=?", (data_out, inode))
            return len(data_out)

        return 0


    async def read(self, fh, off, length):
        log.debug('open %s file (off, length) (%s, %s)' % (fh, off, length))
        data = self.get_row('SELECT data FROM inodes WHERE id=?', (fh,))[0]
        if data is None:
            return b''

        log.debug('data is: %s' % data)
        return data[off:off+length]


    async def write(self, fh, offset, buf):
        log.debug("write (fh, offset, buf) (%s, %s, %s)" % (fh, offset, buf))
        data_old = self.get_row('SELECT data FROM inodes WHERE id=?', (fh,))[0]
        log.debug("old len: %s" % len(data_old))
        log.debug("buf len: %s" % len(buf))
        if data_old is None:
            data_new = b''

        # TODO: check that we replace whole data_old but not edit by chunks
        data_new = buf
#        data_new = data_old[:offset] + buf + data_old[offset+len(buf):]
        log.debug("data_new: %s" % data_new)

        dn = self.get_inode_dn(fh)
        dict_old = ldif.LDIFRecordList(io.StringIO(data_old.decode('utf-8')))
        dict_old.parse()
        log.debug("dict_old: %s" % dict_old.all_records)
        dict_new = ldif.LDIFRecordList(io.StringIO(data_new.decode('utf-8')))
        dict_new.parse()
        log.debug("dict_new: %s" % dict_new.all_records)
        _ldif = modlist.modifyModlist(dict_old.all_records[0][1], dict_new.all_records[0][1])
        log.debug("_ldif: %s" % _ldif)
        self.ad.apply_diff(dn, _ldif)
        self.update_inode_data(fh)
        return len(buf)


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
