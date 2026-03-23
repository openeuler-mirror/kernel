// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "maio.h"
#include "strategy_template.h"

#include <atomic>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

#define MAIO_MNTPOINT "MAIO_MNTPOINT"
#define MAIO_TRACE_FILE "MAIO_TRACE_FILE"
#define CACHEDIR "cachedir"
#define MAXLINE 1024

/* Data structure definition */
enum {
	IO_NONE = 0,
	IO_LOADED,
	IO_EVICTED,
};

struct io {
	string name;
	uint64_t off;
	uint64_t len;
	uint8_t npu;
	int flag;

	explicit io(const string& _name, uint64_t _off, uint64_t _len, uint8_t _npu)
		: name(_name), off(_off), len(_len), npu(_npu), flag(IO_NONE) {}
};


struct ioKey {
	string name;
	uint64_t off;
	uint64_t len;
	uint8_t npu;

	ioKey(const string& _name, uint64_t _off, uint64_t _len, uint8_t _npu)
		: name(_name), off(_off), len(_len), npu(_npu) {}

	bool operator<(const ioKey &other) const {
		return name < other.name || (name == other.name && off < other.off) ||
			(name == other.name && off == other.off && len < other.len);
	}
};

vector<io> iovec; /* io traces */
map<ioKey, int> io_to_index;
unordered_map<int, char*> fd_map;
mutex fd_mutex;
string cachedir;

unordered_map<int, int> npu_numa_map;

unordered_map<int, int> process_npu_map;
mutex pnpu_mutex;

/* for evict */
#define EVICT_DIST 10000
#define EVICT_IO_MAX 5000
thread_local size_t evict_idx = 0;

atomic<int> npu_smi_enable(-1);
atomic<uint64_t> memory_usage(0);

uint64_t memory_limit;
uint64_t memory_limit_bound;
string usage_in_bytes_path = "memory.usage_in_bytes";
string limit_in_bytes_path = "memory.limit_in_bytes";
string cgroup_mem="";

string get_cgroup_path()
{
	fstream cgroup_file("/proc/self/cgroup");
	if (!cgroup_file.is_open()) {
		cerr << "Failed to open /proc/self/cgroup" << endl;
		return "";
	}

	string line;
	string cgroup_path;
	while (getline(cgroup_file, line)) {
		istringstream iss(line);
		string hierarchy, controller, path;
		if (!getline(iss, hierarchy, ':'))
			continue;
		if (!getline(iss, controller, ':'))
			continue;
		if (!getline(iss, path, ':'))
			continue;
		if (controller == "memory") {
			cgroup_path = path;
			break;
		}
	}
	cgroup_file.close();
	return cgroup_path;
}

/* read from /sys/fs/cgroup/memory/memory.[usage_in_bytes|limit_in_bytes] */
uint64_t read_cgroup_memory(const string &file_path)
{
	if (cgroup_mem == "")
		return -1;
	string whole_path = "/sys/fs/cgroup/memory"+cgroup_mem+"/"+file_path;
	ifstream cgroup_file(whole_path);

	if(!cgroup_file.is_open()) {
		cerr << "Failed to open " << file_path << endl;
		return -1;
	}

	string line;
	while(getline(cgroup_file, line)) {
		try {
			return stoll(line);
		} catch (...) {
			cerr << "Failed to parse line" << line << endl;
		}
	}

	cgroup_file.close();
	return -1;
}

/* mount helper */
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

/* fd_map helper function */
char* fd_path_find(int iofd) {
	lock_guard<mutex> lock(fd_mutex);
	auto it = fd_map.find(iofd);
	if (it != fd_map.end()) {
		return it->second;
	} else {
		char *path = _get_fullpath(NULL, iofd);
		size_t len = strlen(path) + cachedir.length() + 1;
		char *realpath = (char*)malloc(len);
		snprintf(realpath, len, "%s%s", cachedir.c_str(), path);
		fd_map.insert({iofd, realpath});
		return realpath;
	}
}

string exec_cmd(const char* cmd) {
	array<char, 128> buffer;
	string result = "";
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

/* cpu_numa_map builder from lscpu */
unordered_map<string, int> build_cpu_numa_map() {
	unordered_map<string, int> cpuNumaMap;
	string result = exec_cmd("lscpu");
	istringstream iss(result);
	string line;

	while (getline(iss, line)) {
		if (line.find("NUMA node") != string::npos) {
			istringstream lineStream(line);
			string key, value;
			int numaNode;
			getline(lineStream, value, ':');
			getline(lineStream, key);
			/* what if numa is more than 10 */
			value = value.substr(value.find("NUMA node") + 9, 1);
			if (!isNumber(value))
				continue;
			numaNode = stoi(value);
			key.erase(0, key.find_first_not_of(" \t"));
			key.erase(key.find_last_not_of(" \t") + 1);
			cpuNumaMap[key]=numaNode;
		}
	}
	return cpuNumaMap;
}

/* npu_numa_map builder, from npu-smi info -t topo */
void build_npu_map_map()
{
	if (npu_smi_enable.load() == -1) {
		if (exec_cmd("command -v npu-smi").empty())
			npu_smi_enable.store(0);
		else
			npu_smi_enable.store(1);
	}

	if (npu_smi_enable.load() == 0)
		return;

	unordered_map<string, int> cpuNumaMap = build_cpu_numa_map();
	string result = exec_cmd("npu-smi info -t topo");
	istringstream iss(result);
	string line;
	size_t target_token_size = 0;

	cout << "NPU\tCPU_AFFINITY\tNUMA_NODE" << endl;
	while (getline(iss, line)) {
		istringstream lineStream(line);
		string npuStr, numaStr, token;
		vector<string> tokens;

		while (lineStream >> token) {
			tokens.push_back(token);
		}

		if (tokens.size() >= 2 && tokens.back() == "Affinity") {
			target_token_size = tokens.size() - 1 + 1;
			continue;
		}

		if (tokens.size() != target_token_size)
			continue;

		int npuId = stoi(tokens[0].substr(3));

		numaStr = tokens.back();
		cout << npuId << "\t" << numaStr << "\t\t" << cpuNumaMap[numaStr] << endl;
		npu_numa_map[npuId] = cpuNumaMap[numaStr];
	}
}

/* process_npu_map builder, from npu-smi info */
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

/* process_npu_map helper */
int process_npu_find(int processid) {
	lock_guard<mutex> lock(pnpu_mutex);
	auto it = process_npu_map.find(processid);

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
	const char *mntpoint = getenv(MAIO_MNTPOINT);
	char *tfilename = getenv(MAIO_TRACE_FILE);
	if(!tfilename || !mntpoint) {
		fprintf(stderr, "no MAIO_TRACE_FILE or MAIO_MNTPOINT env variable\n");
		return -1;
	}
	ifstream tfile(tfilename);
	string line;

	cgroup_mem=get_cgroup_path();
	memory_limit = read_cgroup_memory(limit_in_bytes_path);
	memory_limit_bound = memory_limit * 4 / 5;
	cout << "memory_limit: " << memory_limit << " memory_limit_bound: " << memory_limit_bound << endl;
	get_mount_option(mntpoint, CACHEDIR);
	build_npu_map_map();

	if(!tfile.is_open()) {
		cerr << "Failed to open file:" << tfilename << endl;
		return -1;
	}

	while(getline(tfile, line)) {
		istringstream iss(line);

		string name;
		uint64_t off;
		uint64_t len;
		unsigned int npu;
		if (iss >> name >> off >> len >> npu) {
			iovec.emplace_back(name, off, len, npu);
			io_to_index[ioKey(name, off, len, npu)] = iovec.size() - 1;
		} else {
			cerr << "Failed to parse line:" << line << endl;
		}
	}

	tfile.close();
	return 0;
}

void strategy_exit(void)
{
}

int strategy_load(struct maio **io)
{
	int npuid = process_npu_find((*io)->pid);
	struct maio_entry *entry;
	string pathStr;
	char *path;
	uint64_t idx = iovec.size();
	int ret = 0;
	struct maio *new_io;

	path = fd_path_find((*io)->fd);
	pathStr.assign(path);

	ioKey key(pathStr, (*io)->off, (*io)->len, npuid);
	auto io_it = io_to_index.lower_bound(key);
	if (io_it == io_to_index.end()) {
		entry = (*io)->entries;
		entry[0].toff = (*io)->off + (*io)->len;
		entry[0].tlen = 0;
		entry[0].fpath = NULL;
		entry[0].tnuma = npu_numa_map[npuid];
		return 1;
	}
	if (key < io_it->first) {
		if (io_it != io_to_index.begin()) {
			--io_it;
			if (io_it->first.name != pathStr) {
				++io_it;
			}
		}
	}

	idx = io_it->second;
	(*io)->flags |= MAIO_WITH_SEQ;
	(*io)->curseq = idx;
	entry = (*io)->entries;
	int ios = 0;
	uint64_t memory_usage = read_cgroup_memory(usage_in_bytes_path);
	vector<int> io_extra;

	/* fill ios below max_io */
	while (idx < iovec.size()) {
		if (iovec[idx].flag == IO_LOADED) {
			idx++;
			continue;
		}
		memory_usage += iovec[idx].len / 2;
		if (memory_usage > memory_limit_bound)
			break;
		if (ios >= maio_strategy.max_io) {
			io_extra.push_back(idx);
			goto next_io;
		}
		entry[ios].seq = idx;
		if (pathStr == iovec[idx].name) {
			entry[ios].toff = iovec[idx].off;
			entry[ios].tlen = iovec[idx].len;
			entry[ios].tnuma = npu_numa_map[npuid];
		} else {
			entry[ios].fpath = strdup(iovec[idx].name.c_str());
			entry[ios].toff = iovec[idx].off;
			entry[ios].tlen = iovec[idx].len;
			entry[ios].tnuma = npu_numa_map[iovec[idx].npu];
		}
next_io:
		iovec[idx].flag = IO_LOADED;
		idx++;
		ios++;
	}

	/* fill ios above max_io */
	if (ios > maio_strategy.max_io) {
		new_io = (struct maio *)realloc(*io, sizeof(struct maio) + ios * sizeof(struct maio_entry));
		if (!new_io) {
			printf("failed to alloc ios:%d maio\n", ios);
			return -1;
		}
		*io = new_io;
		entry = (*io)->entries;
		for (int i = maio_strategy.max_io; i < ios; ++i) {
			int io_idx = io_extra[i - maio_strategy.max_io];
			entry[i].seq = io_idx;
			if (pathStr == iovec[io_idx].name) {
				entry[i].toff = iovec[io_idx].off;
				entry[i].tlen = iovec[io_idx].len;
				entry[i].tnuma = npu_numa_map[npuid];
			} else {
				entry[i].fpath = strdup(iovec[io_idx].name.c_str());
				entry[i].toff = iovec[io_idx].off;
				entry[i].tlen = iovec[io_idx].len;
				entry[i].tnuma = npu_numa_map[iovec[io_idx].npu];
			}
		}
	}

	// printf("file:%s off:%lu len:%lu generate_ios:%d from %d",path, (*io)->off, (*io)->len, ios, io_it->second);
	ret = ios;
	return ret;
}

int strategy_evict(struct maio **io)
{
	string pathStr;
	char *path;
	path = fd_path_find((*io)->fd);
	pathStr.assign(path);
	ioKey key(pathStr, (*io)->off, (*io)->len, (*io)->pid);
	auto io_it = io_to_index.lower_bound(key);
	int dist = 0;
	size_t i = 0, io_idx = io_it->second;
	struct maio_entry *entry;
	struct maio *new_io;
	uint64_t evict_memory = 0;
	uint64_t memory_usage = read_cgroup_memory(usage_in_bytes_path);

	if (memory_usage < (memory_limit_bound * 3 / 4))
		return 0;
	dist = io_idx - evict_idx;
	if (dist < 0)
		return 0;
	if (static_cast<size_t>(dist) < iovec.size() / 8 && io_it != io_to_index.end())
		return 0;
	size_t evict_win = 0;
	if (io_it != io_to_index.end()) {
		evict_win = min(iovec.size() / 10, io_idx - 1);
	} else {
		evict_win = dist;
	}

	new_io = (struct maio*)realloc(*io, sizeof(struct maio) + evict_win * sizeof(struct maio_entry));
	if (!new_io)
		return -1;
	*io = new_io;
	entry = new_io->entries;

	for (i = 0; i < evict_win && evict_idx < iovec.size(); ++i) {
		evict_memory += iovec[evict_idx].len;
		if (evict_memory > memory_limit_bound / 8)
			break;
		entry[i].fpath = strdup(iovec[evict_idx].name.c_str());
		entry[i].toff = iovec[evict_idx].off;
		entry[i].tlen = iovec[evict_idx].len;
		evict_idx++;
		iovec[evict_idx].flag = IO_EVICTED;
	}
	return i;
}

const struct maio_operation maio_strategy = {
	.max_io = 500,
	.init	= strategy_init,
	.exit	= strategy_exit,
	.load	= strategy_load,
	.evict	= strategy_evict,
};

struct maio_operation *register_strategy()
{
	return (struct maio_operation *)&maio_strategy;
}
