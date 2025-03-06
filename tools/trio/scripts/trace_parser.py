#! /usr/env python
# SPDX-License-Identifier: GPL-2.0
import os
import sys
import copy
import json
import argparse
import shutil
import hashlib
import subprocess


PATH_IO_DELIMIT = "|"
PATH_PATH_DELIMIT = "@"
IO_IO_DELIMIT = "+"
VAR_DELIMIT = ","


class TraceParser(object):
    def __init__(self, trace_file, output_dir, rootfs):
        self.output = os.path.join(output_dir, "trace.json")
        self.meta = os.path.join(output_dir, "trace.meta")
        self.data = os.path.join(output_dir, "trace.data")
        self.src_file = trace_file
        self.parent = rootfs
        self.trace_map = {}
        self.fpath_map = {}
        self.total_bytes = 0

    @staticmethod
    def get_page_size():
        try:
            size = subprocess.run(["getconf", "PAGESIZE"], capture_output=True, text=True)
            page_size = int(size.stdout.strip())
            return page_size
        except Exception as e:
            print("Exception:%s, set default pagesize is 4096" % str(e))
            return 4096

    @staticmethod
    def merge_partition(entry, items):
        target_begin = entry[0]
        target_end = entry[1]
        prev_begin = 0
        prev_end = 0

        # copy one for operating
        items_bak = copy.deepcopy(items)
        pidx = -1
        # find the insert point
        for item in items:
            curr_begin = item[0]
            curr_end = item[1]
            if curr_begin > target_begin:
                break
            pidx += 1
            prev_begin = curr_begin
            prev_end = curr_end

        # merge prev node
        if pidx != -1:
            if prev_end >= target_begin:
                target_begin = prev_begin
                if target_end < prev_end:
                    target_end = prev_end
                # remove extra overlay item
                del items_bak[pidx]
                # put placeholder
                items_bak.insert(pidx, (0, 0))

        # merge next node
        idx = pidx + 1
        while idx < len(items):
            next_begin = items[idx][0]
            next_end = items[idx][1]
            if target_end < next_begin:
                break
            if target_end < next_end:
                target_end = next_end
            del items_bak[idx]
            # put placeholder
            items_bak.insert(idx, (0, 0))
            idx += 1

        # release old list
        del items
        items_bak.insert(pidx + 1, (target_begin, target_end))
        for item in items_bak:
            # remove placeholder
            if item[0] == 0 and item[1] == 0:
                items_bak.remove(item)
        return items_bak

    def in_blacklist(self, path):
        # not tracker the memory file system
        if (path.startswith("/tmp/") or path.startswith("/proc/")
                or path.startswith("/sys/")):
            return True
        return False

    def parse_trace(self):
        with open(self.src_file, 'r') as f:
            for line in f.readlines():
                buf_list = line.split(',')
                filepath = buf_list[0].strip()
                ino = int(buf_list[1].strip())
                off = int(buf_list[2].strip())
                len = int(buf_list[3].strip())
                real_path = filepath if not self.parent else "%s/%s" % (self.parent, filepath)
                if not os.path.exists(real_path) or not os.path.isfile(real_path):
                    continue

                if self.in_blacklist(filepath):
                    print("Path %s in blacklist should be skip!" % filepath)
                    continue

                # verify file io
                size = int(os.path.getsize(real_path))
                end = len + off
                if off >= size:
                    continue
                if end > size:
                    end = size

                if filepath not in self.trace_map:
                    self.trace_map[filepath] = [(off, end)]
                    self.fpath_map[filepath] = ino
                else:
                    items = self.trace_map[filepath]
                    new_items = TraceParser.merge_partition((off, end), items)
                    self.trace_map[filepath] = new_items

        for value in self.trace_map.values():
            for item in value:
                self.total_bytes += (item[1] - item[0])

    def trans_data(self):
        try:
            with open(self.data, 'rb') as f:
                data = f.read()
            file_hash = hashlib.sha256(data).hexdigest()
            file_hash = os.path.join(os.path.dirname(self.data), file_hash)
            shutil.copyfile(self.data, file_hash)
            print("trace data:%s" % file_hash)
        except Exception as e:
            raise Exception("trans data exception:%s" % str(e))

    def trans_meta(self):
        try:
            all = ""
            f = open(self.meta)
            data = json.load(f)
            entries = data["entries"]
            for entry in entries:
                #name = entry["name"]
                ios = entry["io"]
                ino = entry["ino"]
                ios_str = ""
                for io in ios:
                    target_off = io[0]
                    target_len = io[1]
                    source_off = io[2]
                    if ios_str == "":
                        ios_str = "%d%s%d%s%d" % (target_off, VAR_DELIMIT, target_len, VAR_DELIMIT, source_off)
                        continue
                    ios_str = "%s%s%d%s%d%s%d" % (ios_str, IO_IO_DELIMIT, target_off, VAR_DELIMIT, target_len, VAR_DELIMIT, source_off)
                if all == "":
                    all = "%d%s%s" % (ino, PATH_IO_DELIMIT, ios_str)
                    continue
                all = "%s%s%s%s%s" % (all, PATH_PATH_DELIMIT, ino, PATH_IO_DELIMIT, ios_str)

            # save file
            hashobj = hashlib.sha256()
            hashobj.update(all.encode())
            sha256 = hashobj.hexdigest()
            sha256 = os.path.join(os.path.dirname(self.meta), sha256)
            with open(sha256, 'w') as f:
                f.write(all)
            print("trace meta:%s" % sha256)
        except Exception as e:
            raise Exception("trans meta exception:%s" % str(e))

    @staticmethod
    def dump_map(map, path):
        jsObj = json.dumps(map)
        fd = open(path, 'w')
        fd.write(jsObj)
        fd.close()

    def dump_trace(self):
        TraceParser.dump_map(self.trace_map, self.output)

    def generate_data(self):
        def read_data(path, off, len):
            with open(path, "rb") as fd:
                fd.seek(off, 0)
                text = fd.read(len)
            return text

        def read_zero_data(len):
            tmp_file = "/tmp/zero.bin"
            if not os.path.exists(tmp_file):
                zero_data = b'\x00' * TraceParser.get_page_size()
                with open(tmp_file, 'wb') as f:
                    f.write(zero_data)
            with open(tmp_file, 'rb') as fd:
                fd.seek(0, 0)
                text = fd.read(len)
            return text

        trace_meta = {
            "version": 1,
            "entries": []
        }
        foff = 0
        with open(self.data, "wb") as file:
            for key, value in self.trace_map.items():
                path = key
                real_path = path if not self.parent else "%s/%s" % (self.parent, path)
                if not os.path.exists(real_path):
                    continue
                entry = {
                    "name": path,
                    "ino": self.fpath_map[path],
                    "io": []
                }
                for item in value:
                    off = item[0]
                    len = (item[1] - item[0])
                    data = read_data(real_path, off, len)
                    file.write(data)
                    entry["io"].append((off, len, foff))
                    # padding with zero
                    page_size = TraceParser.get_page_size()
                    pad_len = page_size - (len % page_size)
                    if pad_len != page_size:
                        pad_data = read_zero_data(pad_len)
                        file.write(pad_data)
                        len += pad_len
                    foff += len
                trace_meta["entries"].append(entry)
        TraceParser.dump_map(trace_meta, self.meta)


def main(argv):
    parser = argparse.ArgumentParser('container trace parser')
    parser.add_argument('--trace_file',
                        required=True,
                        type=str,
                        help='trace source')
    parser.add_argument('--output_dir',
                        required=True,
                        type=str,
                        help='output directory')
    parser.add_argument('--root',
                        required=True,
                        type=str,
                        help='root of filter')
    try:
        args = parser.parse_args()
        trace_file = args.trace_file
        output_dir = args.output_dir
        rootfs = args.root
        if not os.path.exists(trace_file) or not os.path.exists(output_dir) \
                or not os.path.exists(rootfs):
            print("Please input the valid path")
            return -1
        parser = TraceParser(trace_file, output_dir, rootfs)
        parser.parse_trace()
        parser.dump_trace()  # metadata to json
        parser.generate_data()
        parser.trans_meta()
        parser.trans_data()

        return 0
    except Exception as e:
        print("page cache build exception:%s" % str(e))
        return -1


if __name__ == '__main__':
    try:
        ret = main(sys.argv[1:])
    except Exception as main_e:
        print(str(main_e))
        ret = -1
    sys.exit(ret)
