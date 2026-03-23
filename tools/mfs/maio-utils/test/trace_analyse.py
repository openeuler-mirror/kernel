def merge_intervals(intervals):
    """
    合并区间
    :param intervals: 区间列表，每个区间是一个元组 (start, end)
    :return: 合并后的区间列表
    """
    if not intervals:
        return []

    # 按起始位置排序
    intervals.sort(key=lambda x: x[0])

    merged = [intervals[0]]
    for current in intervals[1:]:
        last_merged = merged[-1]
        if current[0] <= last_merged[1]:  # 有重叠
            merged[-1] = (last_merged[0], max(last_merged[1], current[1]))
        else:
            merged.append(current)

    return merged

def process_file(input_file):
    """
    处理输入文件
    :param input_file: 输入文件路径
    :return: 每个文件的合并区间和总大小
    """
    from collections import defaultdict

    # 使用字典按文件名分组
    file_intervals = defaultdict(list)

    with open(input_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                print(f"跳过无效行: {line.strip()}")
                continue

            # 解析文件名、起始位置、大小
            filename, start, size = parts[:3]
            start = int(start)
            size = int(size)

            # 计算区间
            end = start + size
            file_intervals[filename].append((start, end))

    # 合并每个文件的区间
    merged_results = {}
    for filename, intervals in file_intervals.items():
        merged_intervals = merge_intervals(intervals)
        # 计算合并后的区间总大小
        total_size = sum(end - start for start, end in merged_intervals)
        merged_results[filename] = {
            "merged_intervals": merged_intervals,
            "total_size": total_size
        }

    return merged_results

def main():
    import sys

    if len(sys.argv) != 2:
        print("用法: python script.py <输入文件>")
        sys.exit(1)

    input_file = sys.argv[1]

    merged_results = process_file(input_file)

    whole_result=0

    for filename, result in merged_results.items():
        print(f"文件: {filename}")
        # print("合并后的区间:")
        # for interval in result["merged_intervals"]:
        #     print(f"起始位置: {interval[0]}, 结束位置: {interval[1]}")
        print(f"所有区间内数据的总大小: {result['total_size']} 字节")
        print("-" * 40)
        whole_result+=result['total_size']
    print(f"所有文件内数据的总大小: {whole_result} 字节")

if __name__ == "__main__":
    main()
