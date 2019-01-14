# Overview

Browse and edit AD LDAP via FUSE

# Install

```
apt-get install libfuse3-devel
pip install -r requirements.txt
```

# Usage

At now when you hit Ctrl+C the module did not unmount FS properly. In
that case you need to umount it by hand via `fusermount -u ./mnt`

```
mkdir ./mnt
./adfs.py --debug ./mnt/
```
