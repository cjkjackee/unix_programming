#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>

#define old_func(name) \
if (old_##name == NULL){ \
    void *handle = dlopen("libc.so.6", RTLD_LAZY); \
    if(handle != NULL) \
        old_##name = dlsym(handle, #name); \
    dlclose(handle); \
}

#define output(format, arg...) \
char *where = getenv("MONITOR_OUTPUT"); \
if (where){ \
	FILE* pfile = old_fopen(where, "a");\
	old_fprintf(pfile, "# %s"format"\n", __FUNCTION__, arg); \
	old_fclose(pfile);\
} \
else \
	old_fprintf(stderr, "# %s"format"\n", __FUNCTION__, arg)



//oldfunction
static DIR* (*old_opendir)(const char* name) = NULL;
static int (*old_closedir)(DIR *dirp) = NULL;
static struct dirent* (*old_readdir)(DIR *dirp) = NULL;
static int (*old_creat)(const char *pathname, mode_t mode) = NULL;
static int (*old_open)(const char *path, int oflag, ... ) = NULL;
static ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;
static int (*old_dup)(int oldfd) = NULL;
static int (*old_dup2)(int oldfd, int newfd) = NULL;
static int (*old_close)(int fd) = NULL;
static int (*old___lxstat)(int ver, const char * path, struct stat * stat_buf) = NULL;
static int (*old___xstat)(int ver, const char * path, struct stat * stat_buf) = NULL;
static ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
static ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
static FILE* (*old_fopen)(const char *pathname, const char *mode) = NULL;
static int (*old_fclose)(FILE *stream) = NULL;
static size_t (*old_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static size_t (*old_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static int (*old_fgetc)(FILE *stream) = NULL;
static char* (*old_fgets)(char *s, int size, FILE *stream) = NULL;
static int (*old_fprintf)(FILE * stream, const char * format, ...) = NULL;
static int (*old_chdir)(const char *path) = NULL;
static int (*old_chown)(const char *pathname, uid_t owner, gid_t group) = NULL;
static int (*old_chmod)(const char *pathname, mode_t mode) = NULL;
static int (*old_remove)(const char *pathname) = NULL;
static int (*old_rename)(const char *oldpath, const char *newpath) = NULL;
static int (*old_link)(const char *oldpath, const char *newpath) = NULL;
static int (*old_unlink)(const char *pathname) = NULL;
static ssize_t (*old_readlink)(const char *pathname, char *buf, size_t bufsiz) = NULL;
static int (*old_symlink)(const char *target, const char *linkpath) = NULL;
static int (*old_mkdir)(const char *pathname, mode_t mode) = NULL;
static int (*old_rmdir)(const char *pathname) = NULL;

char* fd_convert(int fd){
	char fd_path[255];
	char cwd[255];
	char* filename = malloc(255);
	ssize_t n;

	switch(fd){
		case 0:
			return "<STDIN>";
		case 1:
			return "<STDOUT>";
		case 2:
			return "<STDERR>";
		default:
			fd = fd;
	}
	
	sprintf(fd_path, "/proc/self/fd/%d", fd);
	n = old_readlink(fd_path, filename, 255);
	if (n < 0)
		return NULL;
	filename[n] = '\0';

	if(getcwd(cwd, sizeof(cwd)) < 0){
		perror("getcwd() error");
		exit(1);
	}

	if(!strcmp(cwd, filename)){
		sprintf(filename, ".");
		return filename;
	}
		

	strcpy(fd_path, filename);
	if(!strcmp(cwd, dirname(fd_path))){
		strcpy(fd_path, filename);
		sprintf(filename, "./%s", basename(fd_path));
	}
	
	return filename;
}

char* fp_convert(FILE* fp){
	int fd = fileno(fp);
	return fd_convert(fd);
}

char* dp_convert(DIR* dp){
	int fd = dirfd(dp);
	return fd_convert(fd);
}


// main
__attribute__((constructor))void preload_old_fprint_and_fopen(){
	old_func(fprintf)
	old_func(fopen)
	old_func(readlink)
	old_func(fclose)
	return;
}

DIR* opendir(const char* name){
    DIR* ret;

    old_func(opendir)

    ret = old_opendir(name);

    output("(\"%s\") = %p", name, ret);

    return ret;
}

int closedir(DIR *dirp){
    int ret = 0;
	char* dirname = dp_convert(dirp);
    
    old_func(closedir)

    ret = old_closedir(dirp);
    output("(\"%s\") = %d", dirname, ret);

    return ret;
}

struct dirent *readdir(DIR *dirp){
    struct dirent* file;
	char* fileName = NULL;
    
    old_func(readdir)

    file = old_readdir(dirp);
    if (file != NULL)
		fileName = file->d_name;
    else
		fileName = "NULL";

    output("(\"%s\") = %s", dp_convert(dirp), fileName);

    return file;
}

int creat(const char *pathname, mode_t mode){
	int ret;

	old_func(creat)

	ret = old_creat(pathname, mode);
	output("(\"%s\" {mode=%05o}) = %d", pathname, mode&00777, ret);

	return ret;
}

int open(const char *path, int oflag, ... ){
	int ret;
	va_list ap;
	mode_t mode;

	old_func(open)

	va_start(ap, oflag);
	mode = va_arg(ap, int);	
	va_end(ap);

	if (oflag&O_CREAT || oflag&__O_TMPFILE){
		ret = old_open(path, oflag, mode);
		output("(\"%s\", %d {mode=%3o}) = %d", path, oflag, mode&0777, ret);
	}
	else{
		ret = old_open(path, oflag);
		output("(\"%s\", %d) = %d", path, oflag, ret);
	}

	return ret;
}

ssize_t read(int fd, void *buf, size_t count){
	ssize_t ret;

	old_func(read)

	ret = old_read(fd,buf,count);

	output("(\"%s\", %p, %ld) = %ld", fd_convert(fd), buf, count, ret);

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count){
	ssize_t ret;
	
	old_func(write)

	ret = old_write(fd, buf, count);

	output("(\"%s\", %p, %ld) = %ld", fd_convert(fd), buf, count, ret);

	return ret;
}

int dup(int oldfd){
	int ret;

	old_func(dup)

	ret = old_dup(oldfd);

	output("(\"%s\") = %d", fd_convert(oldfd), ret);

	return ret;
}

int dup2(int oldfd, int newfd){
	int ret;

	old_func(dup2)

	ret = old_dup2(oldfd, newfd);

	output("(\"%s\", %d) = %d", fd_convert(oldfd), newfd, ret);

	return ret;
}

int close(int fd){
	int ret;
	char* filename = fd_convert(fd);

	old_func(close);
	
	ret = old_close(fd);

	output("(\"%s\") = %d", filename, ret);

	return ret;
}


int __lxstat(int ver, const char * path, struct stat * stat_buf){
    int ret;
    FILE *pfile;

    old_func(__lxstat)

    ret = old___lxstat(ver, path, stat_buf);

    // output("(\"%s\") = %d", path, ret);
	char *where = getenv("MONITOR_OUTPUT"); 
	if (where){
		pfile = old_fopen(where, "a");
	    old_fprintf(pfile, "# %s(\"%s\", %p {mode=%05o, size=%ld}) = %d\n", "lstat", path, stat_buf, stat_buf->st_mode&00777, stat_buf->st_size, ret); 
	    old_fclose(pfile);
    }
	else 
	    old_fprintf(stderr, "# %s(\"%s\", %p {mode=%05o, size=%ld}) = %d\n", "lstat", path, stat_buf, stat_buf->st_mode&00777, stat_buf->st_size, ret); 

    return ret;
}

int __xstat(int ver, const char * path, struct stat * stat_buf){
	int ret;
	char *where;
	FILE *pfile;

	old_func(__xstat);
	
	ret = old___xstat(ver, path, stat_buf);
	where = getenv("MONITOR_OUTPUT"); 
	if (where){
		pfile = old_fopen(where, "a");
	    old_fprintf(pfile, "# %s(\"%s\", %p {mode=%05o, size=%ld}) = %d\n", "stat", path, stat_buf, stat_buf->st_mode&00777, stat_buf->st_size, ret); 
	    old_fclose(pfile);
    }
	else 
	    old_fprintf(stderr, "# %s(\"%s\", %p {mode=%05o, size=%ld}) = %d\n", "stat", path, stat_buf, stat_buf->st_mode&00777, stat_buf->st_size, ret); 
	return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset){
	ssize_t ret;

	old_func(pread);

	ret = old_pread(fd, buf, count, offset);

	output("(\"%s\", %p, %ld, %ld) = %ld", fd_convert(fd), buf, count, offset, ret);

	return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset){
	ssize_t ret;

	old_func(pwrite);
	
	ret = old_pwrite(fd, buf, count, offset);
	
	output("(\"%s\", %p, %ld, %ld) = %ld", fd_convert(fd), buf, count, offset, ret);

	return ret;
}

FILE *fopen(const char *pathname, const char *mode){
	FILE* ret;

	old_func(fopen)

	ret = old_fopen(pathname, mode);

	if (old_fprintf == NULL)
		preload_old_fprint_and_fopen();
    
    output("(\"%s\", \"%s\") = %p", pathname, mode, ret);

	return ret;
}

int fclose(FILE *stream){
	int ret;
	char* filename = fp_convert(stream);

	old_func(fclose);

	ret = old_fclose(stream);

	output("(\"%s\") = %d", filename, ret);

	return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
	size_t ret;

	old_func(fread)

	ret = old_fread(ptr, size, nmemb, stream);

	output("(%p, %d, %d, \"%s\") = %d", ptr, size, nmemb, fp_convert(stream), ret);

	return ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
	size_t ret;

	old_func(fwrite)

	ret = old_fwrite(ptr, size, nmemb, stream);

	output("(%p, %d, %d, \"%s\") = %d", ptr, size, nmemb, fp_convert(stream), ret);

	return ret;
}

int fgetc(FILE* stream){
    int ret;

    old_func(fgetc)

    ret = old_fgetc(stream);

	output("(\"%s\") = %d", fp_convert(stream), ret);

    return ret;
}

char *fgets(char *s, int size, FILE *stream){
    char* ret;

    old_func(fgets)

    ret = old_fgets(s, size, stream);

    output("(%p, %d, \"%s\") = \"%s\"", s, size, fp_convert(stream), ret);

    return ret;
}

int fscanf(FILE *stream, const char *format, ...){
    int ret;
    va_list arg;

    va_start(arg, format);
    ret = vfscanf(stream, format, arg);
    va_end(arg);

    output("(\"%s\", \"%s\", ...) = %d", fp_convert(stream), format, ret);

    return ret;
}

int fprintf(FILE *stream, const char *format, ...){
	int ret;
	va_list arg;

	va_start(arg, format);
	ret = vfprintf(stream, format, arg);
	va_end(arg);

    output("(\"%s\", \"%s\", ...) = %d", fp_convert(stream), format, ret);

	return ret;
}

int chdir(const char *path){
	int ret;

	old_func(chdir)

	ret = old_chdir(path);

	output("(\"%s\") = %d", path, ret);

	return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group){
	int ret;

	old_func(chown)

	ret = old_chown(pathname, owner, group);

	output("(\"%s\", %d, %d) = %d", pathname, owner, group, ret);

	return ret;
}

int chmod(const char *pathname, mode_t mode){
	int ret;

	old_func(chmod)
	
	ret = old_chmod(pathname, mode);

	output("(\"%s\", mode=%05o) = ret", pathname, mode&00777, ret);

	return ret;
}

int remove(const char *pathname){
	int ret;

	old_func(remove)

	ret = old_remove(pathname);

	output("(\"%s\") = %d", pathname, ret);

	return ret;
}

int rename(const char *oldpath, const char *newpath){
	int ret;

	old_func(rename)

	ret = old_rename(oldpath, newpath);

	output("(\"%s\", \"%s\") = %d", oldpath, newpath, ret);

	return ret;
}

int link(const char *oldpath, const char *newpath){
	int ret;

	old_func(link)

	ret = old_link(oldpath, newpath);

	output("(\"%s\", \"%s\") = %d", oldpath, newpath, ret);

	return ret;
}

int unlink(const char *pathname){
	int ret;

	old_func(unlink)

	ret = old_unlink(pathname);

	output("(\"%s\") = %d", pathname, ret); 

	return ret;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz){
	ssize_t ret;

	old_func(readlink)

	ret = old_readlink(pathname, buf, bufsiz);

	output("(\"%s\", \"%s\", %d) = %d", pathname, buf, bufsiz, ret);

	return ret;
}

int symlink(const char *target, const char *linkpath){
	int ret;

	old_func(symlink)

	ret = old_symlink(target, linkpath);

	output("(\"%s\", \"%s\") = %d", target, linkpath, ret);

	return ret;
}

int mkdir(const char *pathname, mode_t mode){
	int ret;

	old_func(mkdir)

	ret = old_mkdir(pathname, mode);

	output("(\"%s\", mode=%05o) = %d", pathname, mode&0777, ret);

	return ret;
}

int rmdir(const char *pathname){
	int ret;
	
	old_func(rmdir)

	ret = old_rmdir(pathname);

	output("(\"%s\") = %d", pathname, ret);

	return ret;
}