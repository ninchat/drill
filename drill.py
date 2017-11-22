#!/usr/bin/env python3

import argparse
import os
import struct
import sys
from collections import defaultdict
from ctypes import CDLL, c_int, c_long, c_size_t, c_ssize_t, c_void_p, sizeof
from mmap import MAP_PRIVATE, PROT_READ, mmap

NUM_GENERATIONS = 3

PTRACE_ATTACH = 16
PTRACE_DETACH = 17

BLOCK_SIZE = 4096

p_size = sizeof(c_void_p)
p_pack = {4: "I", 8: "Q"}[p_size]

libc = CDLL("libc.so.6")

libc.ptrace.argtypes = [c_int, c_int, c_void_p, c_void_p]
libc.ptrace.restype = c_long


def ptrace(request, pid):
    if libc.ptrace(request, pid, 0, 0) != 0:
        raise Exception("ptrace")


class MemoryMap:

    def __init__(self, *args, **kwargs):
        self._mmap = mmap(*args, **kwargs)

    def slice(self, offset):
        return self._mmap[offset:]

    def close(self):
        self._mmap.close()


class ReadMemory:

    def __init__(self, fil, offset):
        self._file = fil  # Borrowed reference
        self._base = offset
        self._blocks = {}

    def slice(self, offset):
        block_offset = offset & ~(BLOCK_SIZE - 1)
        try:
            b = self._blocks[block_offset]
        except KeyError:
            self._file.seek(self._base + block_offset)
            b = self._blocks[block_offset] = self._file.read(BLOCK_SIZE)
        return b[offset & (BLOCK_SIZE - 1):]

    def close(self):
        pass


class Memory:

    def __init__(self, maps):
        self._maps = maps

    def slice(self, offset):
        for start, end, m in self._maps:
            if offset >= start and offset < end:
                return m.slice(offset - start)
        raise Exception("Data address 0x%x not mapped" % offset)

    def ptr(self, offset):
        return struct.unpack(p_pack, self.slice(offset)[:p_size])[0]

    def int32(self, offset):
        return struct.unpack("i", self.slice(offset)[:4])[0]

    def str(self, offset):
        b = bytearray()
        while True:
            s = self.slice(offset)
            i = s.find(0)
            if i >= 0:
                b.extend(s[:i])
                return b.decode()
            b.extend(s)
            offset += len(s)


offset_gc_head_next = 0
offset_gc_head_prev = offset_gc_head_next + p_size
offset_gc_head_refs = offset_gc_head_prev + p_size
sizeof_gc_head = offset_gc_head_refs + sizeof(c_ssize_t)

offset_gc_generation_head = 0
offset_gc_generation_threshold = offset_gc_generation_head + sizeof_gc_head
offset_gc_generation_count = offset_gc_generation_threshold + sizeof(c_int)
sizeof_gc_generation = offset_gc_generation_count + sizeof(c_int)

offset_object_refcnt = 0
offset_object_type = offset_object_refcnt + sizeof(c_ssize_t)
sizeof_object = offset_object_type + p_size

offset_var_object_base = 0
offset_var_object_size = offset_var_object_base + sizeof_object
sizeof_var_object = offset_var_object_size + sizeof(c_ssize_t)

offset_typeobject_head = 0
offset_typeobject_name = offset_typeobject_head + sizeof_var_object


def drill(mem, gen0_offset):
    type_names = {}
    type_counts = defaultdict(int)

    gc_list = mem.ptr(gen0_offset)

    for i in range(NUM_GENERATIONS):
        gc = mem.ptr(gc_list + offset_gc_head_next)
        while gc != gc_list:
            op = gc + sizeof_gc_head
            typ = mem.ptr(op + offset_object_type)
            type_counts[typ] += 1

            if typ not in type_names:
                name_ptr = mem.ptr(typ + offset_typeobject_name)
                type_names[typ] = mem.str(name_ptr)

            gc = mem.ptr(gc + offset_gc_head_next)

        gc_list += sizeof_gc_generation

    return sorted(((cnt, type_names[typ]) for typ, cnt in type_counts.items()), reverse=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--_PyGC_generation0", type=str)
    parser.add_argument("pid", type=int, help="Python process id to drill")
    args = parser.parse_args()

    pid = args.pid
    gen0_offset = int(args._PyGC_generation0, 0)

    ptrace(PTRACE_ATTACH, pid)
    try:
        status_pid, status = os.waitpid(pid, 0)
        if status_pid != pid:
            raise Exception("waitpid {}".format(pid))
        if not os.WIFSTOPPED(status):
            raise Exception("Process {} did not stop".format(pid))

        try:
            with open("/proc/{}/mem".format(pid), "rb") as memfile:
                maps = []

                with open("/proc/{}/maps".format(pid)) as mapsfile:
                    for line in mapsfile:
                        fields = line.split()
                        start, end = (int(x, 16) for x in fields[0].split("-", 1))
                        perms = fields[1]

                        if "r" in perms:
                            length = end - start

                            if "w" not in perms and len(fields) > 5 and fields[5].startswith("/"):
                                offset = int(fields[2], 16)
                                pathname = fields[5]

                                fd = os.open(pathname, os.O_RDONLY)
                                try:
                                    m = MemoryMap(fd, 0, MAP_PRIVATE, PROT_READ, offset=offset)
                                finally:
                                    os.close(fd)
                            else:
                                m = ReadMemory(memfile, start)

                            maps.append((start, end, m))

                count_types = drill(Memory(maps), gen0_offset)
        finally:
            for start, end, m in maps:
                m.close()
    finally:
        ptrace(PTRACE_DETACH, pid)

    width = len(str(count_types[0][0]))

    for cnt, name in count_types:
        print(("%" + str(width) + "d %s") % (cnt, name))


if __name__ == "__main__":
    main()
