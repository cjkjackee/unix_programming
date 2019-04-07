#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <fstream>
#include <regex>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
using namespace std;

#define tcp_size 16*8+22
#define tcp6_size 16*10+17
#define udp_size 16*8
#define udp6_size 16*10+7
#define ip_size 38

static struct option opts[] = {
	{"tcp", no_argument, NULL, 't'},
	{"udp", no_argument, NULL, 'u'},
	{"help", no_argument, NULL, 'h'}
};

stringstream result;

void err_sys(const char*); 
int open_file(const char* , unsigned int);
int read_file(int, char*, unsigned int);
void show(string, string, string, string);
string codeToIpv4(const char*);
string codeToIpv6(const char*);
string inodeTranslate(const int);
void netstat_tcp();
void netstat_udp();


int main(int argc, char** argv){
	int c;
	string tmp;
	bool once = false;

	while((c = getopt_long(argc, argv, "tuh", opts, NULL)) != -1){
		switch (c)
		{
			case 't':
				netstat_tcp();
				break;
			case 'u':
				netstat_udp();
				break;
			case 'h':
				cout << "usage: " << argv[0] << " [-t|--tcp] [-u|--udp] [filter-string]" << endl;
				break;
			default:
				cout << "usage: " << argv[0] << " [-t|--tcp] [-u|--udp] [filter-string]" << endl;
				break;
		}
	}

	if (optind == 1){
		netstat_tcp();
		result << endl;
		netstat_udp();
	}

	if (optind != argc){
		string reg = argv[optind];
		regex e (reg, regex_constants::icase);

		while(getline(result, tmp)){
			if (tmp.compare("List of TCP connections:") == 0 || tmp.compare("List of UDP connections:") == 0){
				if (once)
					cout << endl;

				cout << tmp << endl;
				getline(result, tmp);
				cout << tmp << endl;
				once = true;
				continue;
			}
			
			if (regex_search(tmp, e))
				cout << tmp << endl;
		}
	}
	else{
		while(getline(result, tmp))
			cout << tmp << endl;
	}

	return 0;
}



/********************** function **************************/

void err_sys(const char* c){
	perror(c);
	exit(1);
}

int open_file(const char* path, unsigned int buf_size){
	int n;

	n = open(path, O_RDONLY|O_APPEND);
	if (n < 0)
		err_sys("open error");

	// skip col description
	if (lseek(n, buf_size, SEEK_CUR) == -1)
		err_sys("lseek error");

	return n;
}

int read_file(int file, char* buffer, unsigned int buf_size){
	int n;

	memset(buffer, 0, tcp6_size);
	if ((n = read(file, buffer, buf_size)) < 0){
		err_sys("read error");	
	}
	return n;
}

void show(string proto, string local, string foreign, string pid){
	int ip_space = 30;
	result << std::left << setw(6) << proto;
	result << std::left << setw(ip_space) << local;
	result << std::left << setw(ip_space) << foreign << pid << endl;
	return;
}

string codeToIpv4(const char* code){
	string ret;
	char ip[INET_ADDRSTRLEN];
	unsigned int port;
	struct in_addr address;

	memset(&address, 0, sizeof(address));
	sscanf(code, "%x:%x", (unsigned int*)&address, &port);
	inet_ntop(AF_INET, (void*)&address, ip, INET_ADDRSTRLEN);
	ret = ip;
	ret.append(":");
	if (port > 0)
		ret.append(to_string(port));
	else
		ret.append("*");

	return ret;
}

string codeToIpv6(const char* code){
	string ret;
	char ip[INET6_ADDRSTRLEN];
	unsigned int port;
	struct in6_addr address;

	memset(&address, 0, sizeof(address));
	sscanf(code, "%8x%8x%8x%8x:%x", &address.s6_addr32[0], &address.s6_addr32[1], &address.s6_addr32[2], &address.s6_addr32[3], &port);
	inet_ntop(AF_INET6, (void*)&address.s6_addr32, ip, INET6_ADDRSTRLEN);
	ret = ip;
	ret.append(":");
	if (port > 0)
		ret.append(to_string(port));
	else 
		ret.append("*");

	return ret;
}

string inodeTranslate(const int inode){
	string ret;
	DIR* proc;
	DIR* pid;
	string path = "/proc/";
	struct dirent* dir;
	char* link;
	struct stat sb;
	ssize_t nbytes, bufsize;
	bool flag = false;

	proc = opendir(path.c_str());
	if (proc == NULL)
		err_sys("inodeTranslate: opendir error");
	
	while((dir = readdir(proc)) != NULL){
		if (dir->d_type==DT_DIR && atoi(dir->d_name)>0){
			ret = dir->d_name;
			string cpath = path + dir->d_name + "/fd/";

			pid = opendir(cpath.c_str());
			if (pid == NULL)
				continue;

			while((dir = readdir(pid)) != NULL){
				string tmp;
				char buf[PATH_MAX];
				int node;

				if (dir->d_type != DT_LNK)
					continue;

				tmp = cpath + dir->d_name;
				if (lstat(tmp.c_str(), &sb) == -1)
					err_sys("lstat error");
				
				if (sb.st_size == 0)
					bufsize = PATH_MAX;
				else
					bufsize = sb.st_size + 1;

				link = (char*)malloc(bufsize);
				if (link == NULL)
					err_sys("malloc error");

				nbytes = readlink(tmp.c_str(), link, bufsize);
				if (nbytes == -1)
					err_sys("readlink error");

				sprintf(buf, "%*s\n", (int)nbytes, link);
				free(link);

				sscanf(buf, "socket:[%d]", &node);
				if (node == inode){
					flag = true;
					break;
				}
			}
			closedir(pid);

			if (flag){
				string tmp;
				fstream fs;
				cpath = path + ret + "/comm";

				fs.open(cpath, fstream::in);
				fs >> tmp;
				fs.close();

				return ret + "/" + tmp;	
			}
		}
	}
	closedir(proc);

	return "-";
}

void netstat_tcp(){
	int tcp_fd, tcp6_fd;
	char buffer[tcp6_size];
	char local[ip_size], foreign[ip_size];
	int inode;

	result << "List of TCP connections:" << endl;
	show("Proto", "Local Address", "Foreign Address", "Pid/Program name and arguments");

	tcp_fd = open_file("/proc/net/tcp", tcp_size);
	while(read_file(tcp_fd, buffer, tcp_size) == tcp_size){
		sscanf(buffer, "%*s %s %s %*s %*s %*s %*s %*s %*s %d", local, foreign, &inode);
		show("tcp", codeToIpv4(local), codeToIpv4(foreign), inodeTranslate(inode));
	}
	close(tcp_fd);

	tcp6_fd = open_file("/proc/net/tcp6", 16*9+1);
	while(read_file(tcp6_fd, buffer, tcp6_size) == tcp6_size){
		sscanf(buffer, "%*s %s %s %*s %*s %*s %*s %*s %*s %d", local, foreign, &inode);
		show("tcp6", codeToIpv6(local), codeToIpv6(foreign), inodeTranslate(inode));
	}
	close(tcp6_fd);

	return;
}

void netstat_udp(){
	int udp_fd, udp6_fd;
	char buffer[tcp6_size];
	char local[ip_size], foreign[ip_size];
	int inode;

	result << "List of UDP connections:" << endl;
	show("Proto", "Local Address", "Foreign Address", "Pid/Program name and arguments");

	udp_fd = open_file("/proc/net/udp", udp_size);
	while(read_file(udp_fd, buffer, udp_size) == udp_size){
		sscanf(buffer, "%*s %s %s %*s %*s %*s %*s %*s %*s %d", local, foreign, &inode);
		show("udp", codeToIpv4(local), codeToIpv4(foreign), inodeTranslate(inode));
	}
	close(udp_fd);

	udp6_fd = open_file("/proc/net/udp6", 16*10+2);
	while(read_file(udp6_fd, buffer, udp6_size) == udp6_size){
		sscanf(buffer, "%*s %s %s %*s %*s %*s %*s %*s %*s %d", local, foreign, &inode);
		show("udp6", codeToIpv6(local), codeToIpv6(foreign), inodeTranslate(inode));
	}
	close(udp6_fd);

	return;
}
