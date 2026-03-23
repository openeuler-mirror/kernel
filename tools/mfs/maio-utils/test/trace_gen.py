import argparse
import os
import sys

FILENAME_IDX = 0
OFF_IDX = 1
LEN_IDX = 2
NUMA_IDX = 3
OFF_BOUND = 1024 * 1024 * 4096

class ReplayHintGenerator(object):
    def __init__(self, trace_file, output_file):
        self.output_file = output_file
        self.trace_file = trace_file
        self.data_list = []

    def generate_hint(self):
        with open(self.output_file, 'w') as f:
            for data in self.data_list:
                data_off = data[OFF_IDX]
                data_len = data[LEN_IDX]
                print(data_off)
                step = (512 * 1024 * 1024)
                while data_len:
                    if data_len < step:
                        step = data_len
                    print(f"{data[FILENAME_IDX]} {data_off} {step} {data[NUMA_IDX]}", file=f)
                    data_len-=step
                    data_off+=step

    def parse_trace(self):
        file_map_index={}
        with open(self.trace_file, 'r') as f:
            for line in f:
                parts = line.strip().split(' ')

                filename, off, length, numaid = parts
                off = int(off)
                length = int(length)
                numaid = int(numaid)
                if self.data_list:
                    tail_data = self.data_list[-1]
                    '''
                    首先尝试跟末尾的数据合并:
                    如若跟末尾的数据是同一个文件跟numaid,
                    两者之间的距离小于设定值,
                    就进行合并
                    '''
                    if (tail_data[FILENAME_IDX] == filename and tail_data[NUMA_IDX] == numaid):
                        tail_off = tail_data[OFF_IDX]
                        tail_end = tail_data[OFF_IDX] + tail_data[LEN_IDX]
                        end = off + length
                        abs_off = max(abs(off - tail_end), abs(tail_off - end))
                        if abs_off < OFF_BOUND:
                            tail_data[OFF_IDX] = min(tail_off, off)
                            tail_data[LEN_IDX] = max(tail_end, end) - tail_data[OFF_IDX]
                            continue
                    else:
                        '''
                        否则跟之前同一文件和numaid的数据进行合并
                        如若两者之间距离小于设定值，
                        就进行合并
                        '''
                        key = (filename, numaid)
                        if key in file_map_index:
                            index = file_map_index[key]
                            data = self.data_list[index]
                            data_off = data[OFF_IDX]
                            data_end = data[OFF_IDX] + data[LEN_IDX]
                            end = off + length
                            abs_off = max(abs(off - data_end), abs(data_off - end))
                            if abs_off < OFF_BOUND:
                                data[OFF_IDX] = min(data_off, off)
                                data[LEN_IDX] = max(data_end, end) - data[OFF_IDX]
                                continue
                self.data_list.append([filename, off, length, numaid])
                file_map_index[(filename, numaid)] = len(self.data_list) - 1


def main(agrv):
    """
    Parse the argument
    """
    parser = argparse.ArgumentParser('model trace parser')
    parser.add_argument('--trace_file',
                        required=True,
                        type=str,
                        help='trace source')
    parser.add_argument('--output_file',
                        required=True,
                        type=str,
                        help='output of hint file')
    try:
        args = parser.parse_args()
        trace_file = args.trace_file
        output_file = args.output_file
        if not os.path.exists(trace_file):
            print("{trace_file} not exist")
            return -1

        hint_generator=ReplayHintGenerator(trace_file, output_file)
        hint_generator.parse_trace()
        hint_generator.generate_hint()
        return 0
    except Exception as e:
        print(f"Parse model trace exception:{str(e)}")
        return -1

if __name__ == '__main__':
    try:
        ret = main(sys.argv[1:])
    except Exception as main_e:
        print(str(main_e))
        ret = -1
    sys.exit(ret)

