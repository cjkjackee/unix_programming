# hw2

- [\_\_attribute__((constructor)) usage](https://www.jianshu.com/p/dd425b9dc9db)
- [c macro](https://gcc.gnu.org/onlinedocs/cpp/Macros.html#Macros)
- dir pointer to fd
	- dirfd()
- [fd to file name](https://stackoverflow.com/questions/11221186/how-do-i-find-a-filename-given-a-file-pointer?lq=1)
    - 這個方法找到的是絕對路徑，可以通過dirname()和getcwd()對比查看是不是current working path, 是的話可以用basename()抓filename, 改成'./filename'的形式
    - basename()和dirname()在function裏面可能會有小問題
        - [basename() && dirname() change the variable](https://www.unix.com/programming/114966-basename-dirname-changes-value-argument.html)
- [actual stat() defination](http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/baselib-xstat-1.html)
	- function stat() and lstat() their *name* and *variables* are not same as the man page show 
