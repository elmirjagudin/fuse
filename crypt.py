#!/usr/bin/env python
import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations


class File:
    def __init__(self, data=bytearray()):
        self.data = data
        self.open_handles = 1

    def write(self, data, offset):
        new_data_len = len(data)
        missing_len = (offset + new_data_len) - len(self.data)

        if missing_len > 0:
            # we need to extend our data buffer
            self.data.extend([0]*(missing_len-1))

        self.data[offset:offset+new_data_len-1] = data


class FilesCache:
    def __init__(self, root):
        self.root = root
        self.files = {}

    def create(self, path):
        self.files[path] = File()

    def open(self, path, data):
        assert path is not self.files  # TODO handle multiple open on same file?
        self.files[path] = File(data)

    def write(self, path, data, offset):
        f = self.files[path]
        f.write(data, offset)

    def get_ciphertext(self, path):
        f = self.files[path]
        return f.data

    def get_plaintext(self, path):
        f = self.files[path]
        return f.data

    def release(self, path):
        f = self.files[path]
        f.open_handles -= 1
        if f.open_handles <= 0:
            del self.files[path]


class Crypt(Operations):
    def __init__(self, root):
        self.root = root  # TODO use files.root ?
        self.files = FilesCache(root)

    #
    # helpers
    #
    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    #
    # filesystem methods
    #
    def access(self, path, mode):
        print(f"access(path={path}, mode={mode})")
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        print(f"chmod(self, path, mode)")
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        print(f"chown(self, path, uid, gid)")
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        print(f"getattr(path={path}, fh={fh})")
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        print(f"readdir(self, path, fh)")
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        print(f"readlink(self, path)")
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        print(f"mknod(self, path, mode, dev)")
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        print(f"rmdir(self, path)")
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        print(f"mkdir(self, path, mode)")
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        print(f"statfs(self, path)")
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        print(f"unlink(path={path})")
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        print(f"symlink(self, name, target)")
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        print(f"rename(self, old, new)")
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        print(f"link(self, target, name)")
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        print(f"utimens(self, path, times=None)")
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        print(f"open(path={path}, flags={flags})")
        # TODO handle flags properly

        full_path = self._full_path(path)
#        with open(full_path, "rb") as f:
#            self.files.open(path, f.read())
        self.files.open(path, bytearray())

        print(f"open full_path={full_path}")
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        print(f"create(path={path}, mode={mode}, fi={fi})")

        full_path = self._full_path(path)
        fd = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        self.files.create(path)

        return fd

    def read(self, path, length, offset, fh):
        print(f"read(path={path}, length={length}, offset={offset}, fh={fh})")

        data = self.files.get_plaintext(path)
        # TODO handle cases reading beyound end of data ?
        # e.g. when offset + length > len(data)

        return data[offset:offset+length]

    def write(self, path, buf, offset, fh):
        print(f"write(path={path}, buf=..., offset={offset}, fh={fh})")
        self.files.write(path, buf, offset)
        return len(buf)

    def truncate(self, path, length, fh=None):
        print(f"truncate(self, path, length, fh=None)")

        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print(f"1flush(path={path}, fh={fh})")

        try:

            os.lseek(fh, 0, os.SEEK_SET)
            r = os.write(fh, self.files.get_ciphertext(path))
            # TODO, check value of r, handle partial writes?

            r = os.fsync(fh)
            print(f"2flush(path={path}, fh={fh}) = {r}")
            return r
        except Exception as e:
            print("BAH", e)

    def release(self, path, fh):
        self.files.release(path)
        r = os.close(fh)

        print(f"release(path={path}, fh={fh}) = {r}")
        return r

    def fsync(self, path, fdatasync, fh):
        print(f"fsync(path={path}, fdatasync={fdatasync}, fh={fh})")
        return self.flush(path, fh)


def main(mountpoint, root):
    FUSE(Crypt(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])