#!/usr/bin/env python
import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations


# dummy cryto functions
def _encrypt(data):
    return bytearray(data)
    #return bytearray(reversed(data))


def _decrypt(data):
    return bytearray(data)
    #return bytearray(reversed(data))


class File:
    def __init__(self, file_handle, encrypted_data=None):
        self.file_handle = file_handle

        if encrypted_data is None:
            self.data = bytearray()
        else:
            self.data = _decrypt(encrypted_data)

        self.open_handles = 1
        self.dirty = False

    def write(self, data, offset):
        self.dirty = True

        new_data_len = len(data)
        missing_len = (offset + new_data_len) - len(self.data)

        if missing_len > 0:
            # we need to extend our data buffer
            self.data.extend([0]*(missing_len-1))

        self.data[offset:offset+new_data_len-1] = data

    def truncate(self, length):
        cur_len = len(self.data)

        if cur_len == length:
            # already correct length, NOP
            return

        self.dirty = True

        if length < cur_len:
            # we need to make truncate our data buffer
            self.data = self.data[:length]
            return

        assert length > cur_len

        # we need to grow data, fill with zeros
        self.data.extend([0] * ((length - cur_len) - 1))


class FilesCache:
    def __init__(self, root):
        self.root = root
        self.files = {}
        self.next_fh = 0

    def next_file_handle(self):
        nh = self.next_fh
        self.next_fh += 1

        return nh

    def create(self, path):
        f = File(self.next_file_handle())
        self.files[path] = f
        return f

    def open(self, path, data):
        assert path is not self.files  # TODO handle multiple open on same file?

        fo = File(self.next_file_handle(), data)
        self.files[path] = fo

        return fo

    def write(self, path, data, offset):
        f = self.files[path]
        f.write(data, offset)

    def truncate(self, path, length):
        f = self.files[path]
        f.truncate(length)

    def get_ciphertext(self, path):
        f = self.files[path]
        return _encrypt(f.data)

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
        return dict((key, getattr(st, key)) for key in ("st_atime", "st_ctime",
                     "st_gid", "st_mode", "st_mtime", "st_nlink", "st_size", "st_uid"))

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
        print(f"utimens(path={path}, times={times})")
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        print(f"open(path={path}, flags={flags})")
        # TODO handle flags properly

        full_path = self._full_path(path)
        with open(full_path, "rb") as f:
            fo = self.files.open(path, f.read())

        return fo.file_handle

    def create(self, path, mode, fi=None):
        print(f"create(path={path}, mode={mode}, fi={fi})")

        full_path = self._full_path(path)
        os.close(os.open(full_path, os.O_WRONLY | os.O_CREAT, mode))
        f = self.files.create(path)

        return f.file_handle

    def read(self, path, length, offset, fh):
        try:
            print(f"read(path={path}, length={length}, offset={offset}, fh={fh})")
            data = self.files.get_plaintext(path)
            # TODO handle cases reading beyound end of data ?
            # e.g. when offset + length > len(data)

            return bytes(data[offset:offset+length])
        except:
            print("read BAH")

    def write(self, path, buf, offset, fh):
        print(f"write(path={path}, buf=..., offset={offset}, fh={fh})")
        self.files.write(path, buf, offset)
        return len(buf)

    def truncate(self, path, length, fh=None):
        print(f"truncate(path={path} length={length} fh={fh})")
        self.files.truncate(path, length)

    def _do_flush(self, path):
        # TODO only flush dirty files
        full_path = self._full_path(path)
        with open(full_path, "wb") as f:
            f.write(self.files.get_ciphertext(path))

    def flush(self, path, fh):
        print(f"flush(path={path} fh={fh})")
        self._do_flush(path)

    def release(self, path, fh):
        print(f"release(path={path}, fh={fh})")
        self._do_flush(path)
        self.files.release(path)

    def fsync(self, path, fdatasync, fh):
        print(f"fsync(path={path}, fdatasync={fdatasync}, fh={fh})")
        return self.flush(path, fh)


def main(mountpoint, root):
    FUSE(Crypt(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])