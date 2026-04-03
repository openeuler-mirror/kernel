// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "maio.h"
#include "strategy_template.h"

#include <array>
#include <atomic>
#include <cstring>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unistd.h>

using namespace std;

#define MAIO_MNTPOINT "MAIO_MNTPOINT"
#define MAIO_TRACE_FILE "MAIO_TRACE_FILE"
#define CACHEDIR "cachedir"

#define MAXLINE 1024

/* Data struct definition */
template<typename T>
class SafeQueue {
private:
	queue<T> data_queue;
	mutex mtx;
	condition_variable cv;

public:
	// 添加数据到队列
	void push(T item) {
		lock_guard<mutex> lock(mtx);
		data_queue.push(move(item));
		cv.notify_one();
	}

	// 从队列取出数据（阻塞直到有数据）
	T pop() {
		unique_lock<mutex> lock(mtx);
		cv.wait(lock, [this]{ return !data_queue.empty(); });
		T item = move(data_queue.front());
		data_queue.pop();
		return item;
	}

	// 检查队列是否为空
	bool empty() {
		lock_guard<mutex> lock(mtx);
		return data_queue.empty();
	}
};

struct io {
	string name;
	uint64_t off;
	uint64_t len;
	uint8_t npu;

	io(const string& _name, uint64_t _off, uint64_t _len, uint8_t _npu)
		: name(_name), off(_off), len(_len), npu(_npu) {}
};

/* Global variable definition */
unordered_map<int, char*> fd_map; /* map fd to path */
mutex fd_mutex;
string cachedir;

vector<io> iovec; /* io traces */
mutex iovec_mutex;
SafeQueue<vector<io>> iovec_queue;

ofstream tfile; /* trace file */

thread writer;

unordered_map<int, int> process_npu_map;
mutex pnpu_mutex;

atomic<int> npu_smi_enable(-1);

/* fd_map helper function */
char* fd_path_find(int iofd) {
	lock_guard<mutex> lock(fd_mutex);
	auto it = fd_map.find(iofd);
	if (it != fd_map.end()) {
		return it->second;
	} else {
		char *path = _get_fullpath(NULL, iofd);
		fd_map.insert({iofd, path});
		return path;
	}
}

/* iovec helper function */
void io_insert_data(string name, uint64_t off, uint64_t len, uint8_t npu)
{
	lock_guard<mutex> lock(iovec_mutex);
	iovec.emplace_back(name, off, len, npu);

	vector<io> copy_iovec = move(iovec);
	iovec.clear();

	iovec_queue.push(move(copy_iovec));
}

void get_mount_option(const char* mntpoint, const char* option)
{
	ifstream mounts("/proc/mounts");
	string line, target_mp;

	if (!mounts.is_open()) {
		cerr << "Error: could not open /proc/mounts" << endl;
		return;
	}

	while (getline(mounts, line)) {
		istringstream iss(line);
		string device, mp, fs_type, options;

		if (!(iss >> device >> mp >> fs_type >> options))
			continue;

		if (mp.back() != '/')
			mp += '/';
		target_mp = mntpoint;
		if (target_mp.back() != '/')
			target_mp += '/';

		if (target_mp == mp) {
			istringstream opt_stream(options);
			string opt;

			while (getline(opt_stream, opt, ',')) {
				if (opt.find(option) == 0) {
					if (opt[strlen(option)] == '=') {
						cachedir = opt.substr(strlen(option) + 1);
					}
				}
			}
			break;
		}
	}
}

void writer_thread() {
	while (true) {
		vector<io> iovec_to_write = iovec_queue.pop();

		for (const auto &item : iovec_to_write)
			tfile << cachedir << item.name << " " << item.off << " " << item.len << " " << (unsigned int)item.npu << endl;
		tfile.flush();
	}
}

string exec_cmd(const char* cmd) {
	array<char, 128> buffer;
	string result;
	unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

bool isNumber(const std::string& str) {
	return !str.empty() && str.find_first_not_of("0123456789") == std::string::npos;
}

void get_npu_info(string &npuinfo)
{
	istringstream iss(npuinfo);
	string line;

	while (getline(iss, line)) {
		istringstream lineStream(line);
		string token;
		vector<string> tokens;
		while (getline(lineStream, token, ' ')) {
			if (!token.empty()) {
				tokens.push_back(token);
			}
		}
		if (tokens.size() >= 3) {
			if (!isNumber(tokens[1]) || !isNumber(tokens[4]))
				continue;
			int npuId = stoi(tokens[1]);
			int processId = stoi(tokens[4]);
			process_npu_map[processId] = npuId;
		}
	}
}

int process_npu_find(int processid) {
	lock_guard<mutex> lock(pnpu_mutex);
	auto it = process_npu_map.find(processid);

	if (npu_smi_enable.load() == -1) {
		if (exec_cmd("command -v npu-smi").empty())
			npu_smi_enable.store(0);
		else
			npu_smi_enable.store(1);
	}

	if (npu_smi_enable.load() == 0)
		return 0;

	if (it != process_npu_map.end()) {
		return it->second;
	} else {
		string result = exec_cmd("npu-smi info");
		get_npu_info(result);
		auto it = process_npu_map.find(processid);
		if (it != process_npu_map.end())
			return it->second;
		else
			return 0;
	}
}

int strategy_init(void)
{
	char *tfilename = getenv(MAIO_TRACE_FILE);
	char *mntpoint = getenv(MAIO_MNTPOINT);

	if(!tfilename || !mntpoint) {
		printf("no MAIO_TRACE_FILE or MAIO_MNTPOINT env variable\n");
		return -1;
	}
	get_mount_option(mntpoint, CACHEDIR);
	string stfilename = tfilename;
	tfile.open(stfilename, ios::trunc);
	writer = thread(writer_thread);
	if (!tfile.is_open()) {
		cerr << "Error: could not open" << stfilename << endl;
		return -1;
	}
	return 0;
}

void strategy_exit(void)
{
	lock_guard<mutex> lock(iovec_mutex);
	vector<io> copy_iovec = move(iovec);
	iovec.clear();
	iovec_queue.push(move(copy_iovec));

	tfile.close();
	writer.join();
}

int strategy_load(struct maio **io)
{
	char *path;
	string pathStr;
	int ret = 0;

	if (!tfile.is_open())
		return -1;

	path = fd_path_find((*io)->fd);
	pathStr.assign(path);
	io_insert_data(pathStr, (*io)->off, (*io)->len, process_npu_find((*io)->pid));

	return ret;
}

int strategy_evict(struct maio **io)
{
	((void)io);
	return 0;
}

const struct maio_operation maio_strategy = {
	.max_io = 1,
	.init	= strategy_init,
	.exit	= strategy_exit,
	.load	= strategy_load,
	.evict	= strategy_evict,
};

struct maio_operation *register_strategy()
{
	return (struct maio_operation *)&maio_strategy;
}
