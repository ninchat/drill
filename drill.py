#!/usr/bin/env python3

import argparse
import os
import struct
import sys
from collections import defaultdict
from ctypes import CDLL, c_int, c_long, c_size_t, c_ssize_t, c_void_p, sizeof
from os.path import realpath

NUM_GENERATIONS = 3

PTRACE_ATTACH = 16
PTRACE_DETACH = 17

BLOCK_SIZE = 4096

ptr_size = sizeof(c_void_p)
ptr_pack = {4: "I", 8: "Q"}[ptr_size]

ssize_size = sizeof(c_void_p)
ssize_pack = {4: "i", 8: "q"}[ssize_size]

libc = CDLL("libc.so.6")
libc.ptrace.argtypes = [c_int, c_int, c_void_p, c_void_p]
libc.ptrace.restype = c_long


def ptrace(request, pid):
    if libc.ptrace(request, pid, 0, 0) != 0:
        raise Exception("ptrace")


class LazyMemory:

    def __init__(self, pid):
        self._blocks = {}
        self._file = open("/proc/{}/mem".format(pid), "rb")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._file.close()

    def slice(self, offset):
        block_offset = offset & ~(BLOCK_SIZE - 1)
        try:
            b = self._blocks[block_offset]
        except KeyError:
            self._file.seek(block_offset)
            b = self._blocks[block_offset] = self._file.read(BLOCK_SIZE)
        return b[offset & (BLOCK_SIZE - 1):]

    def ptr(self, offset):
        return struct.unpack(ptr_pack, self.slice(offset)[:ptr_size])[0]

    def ssize(self, offset):
        return struct.unpack(ssize_pack, self.slice(offset)[:ssize_size])[0]

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
offset_gc_head_prev = offset_gc_head_next + ptr_size
offset_gc_head_refs = offset_gc_head_prev + ptr_size
sizeof_gc_head = offset_gc_head_refs + sizeof(c_ssize_t)

offset_gc_generation_head = 0
offset_gc_generation_threshold = offset_gc_generation_head + sizeof_gc_head
offset_gc_generation_count = offset_gc_generation_threshold + sizeof(c_int)
sizeof_gc_generation = offset_gc_generation_count + sizeof(c_int)

offset_object_refcnt = 0
offset_object_type = offset_object_refcnt + sizeof(c_ssize_t)
sizeof_object = offset_object_type + ptr_size

offset_var_object_base = 0
offset_var_object_size = offset_var_object_base + sizeof_object
sizeof_var_object = offset_var_object_size + sizeof(c_ssize_t)

offset_typeobject_head = 0
offset_typeobject_name = offset_typeobject_head + sizeof_var_object
offset_typeobject_basicsize = offset_typeobject_name + ptr_size


def drill(mem, gen0_offset):
    type_names_sizes = {}
    type_counts = defaultdict(int)

    gc_list = mem.ptr(gen0_offset)

    for i in range(NUM_GENERATIONS):
        gc = mem.ptr(gc_list + offset_gc_head_next)
        while gc != gc_list:
            op = gc + sizeof_gc_head
            t = mem.ptr(op + offset_object_type)
            type_counts[t] += 1

            if t not in type_names_sizes:
                name = mem.str(mem.ptr(t + offset_typeobject_name))
                size = mem.ssize(t + offset_typeobject_basicsize)
                type_names_sizes[t] = [name, sizeof_gc_head + size]

            gc = mem.ptr(gc + offset_gc_head_next)

        gc_list += sizeof_gc_generation

    return (type_names_sizes[t] + [count] for t, count in type_counts.items())


def adjust_addr(pid, pathname, disp, addr):
    maps = "/proc/{}/maps".format(pid)

    with open(maps) as f:
        for line in f:
            fields = line.strip().split()

            if len(fields) > 5 and fields[5] == pathname:
                start, end = (int(x, 16) for x in fields[0].split("-", 1))
                offset = int(fields[2], 16)

                if addr >= disp + offset and addr < disp + offset + (end - start):
                    return start + addr - (disp + offset)

    raise Exception("Data address 0x{:x} mapped from {} not found in {}".format(addr, pathname, maps))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", metavar="BINARY", type=str, default=realpath(sys.executable))
    parser.add_argument("data_address", type=str, help=".data section address in Python binary")
    parser.add_argument("data_offset", type=str, help=".data section offset in Python binary")
    parser.add_argument("gen0_address", type=str, help="_PyGC_generation0 symbol address in Python binary")
    parser.add_argument("pid", type=int, help="Python process id")
    args = parser.parse_args()

    data_disp = int(args.data_address, 0) - int(args.data_offset, 0)
    gen0_addr = int(args.gen0_address, 0)
    pid = args.pid

    ptrace(PTRACE_ATTACH, pid)
    try:
        status_pid, status = os.waitpid(pid, 0)
        if status_pid != pid:
            raise Exception("waitpid {}".format(pid))
        if not os.WIFSTOPPED(status):
            raise Exception("Process {} did not stop".format(pid))

        proc_gen0_addr = adjust_addr(pid, args.python, data_disp, gen0_addr)

        with LazyMemory(pid) as mem:
            types = drill(mem, proc_gen0_addr)
    finally:
        ptrace(PTRACE_DETACH, pid)

    totals = sorted(((size * count, count, name) for name, size, count in types), reverse=True)
    sumtotal = sum(total for total, count, name in totals)
    sumcount = sum(count for total, count, name in totals)

    fmt = "{:>" + str(len(str(sumcount))) + "} {:>" + str(len(str(sumtotal))) + "}"

    print(fmt.format("COUNT", "MEMORY"))
    print(fmt.format(sumcount, sumtotal), "100%")
    print()

    for total, count, name in totals:
        print(fmt.format(count, total), "{:3}%".format(100 * total // sumtotal), name)


if __name__ == "__main__":
    main()
