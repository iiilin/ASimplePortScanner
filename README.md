# ASimplePortScanner
单文件无依赖Python端口扫描脚本，支持一些简单漏洞的探测

方便丢到 Webshell 上跑，但是动静可能会有点大，可以先用 U 参数（NBNS）跑一波 

比赛什么的就无所谓了

默认 TCP UDP 都跑

默认端口：21-23,25,80,81,110,135,137,139,445,873,1433,1521,3306,3389,6379,7001,8000,8069,8080-8090,9000,9001,10051,11211

UDP 的可以自己加

~~缺点，一个 ip 开一个线程，所以没法 Keyboardinterrupt 结束，有空改成用队列~~

已改成队列用队列，可以用 Keyboardinterrupt 了
另外 修复了 445 端口的编码问题
更新的 NBNS 的解析方式（可能不靠谱）

修改 Python2.6 时的 decode() 的坑及一些杂七杂八的编码问题（可能没修完）

另外就是 optparse 对输入进行解析，这个库 Python2.6 也自带了~

## 功能:
- 多线程端口，获取 banner 信息
- 提取 HTTP HTTPS 协议中的有效信息，返回头中 Server、Location， 返回体中 <title>
- 通过 NBNS 协议获取主机名 (UDP 137)
- Redis 检测未授权
- MS17-010 检测 (抄了巡风的脚本)
- 通过 445 检测 Windows 的版本 (抄了 17-010 的 PHP 脚本)

## 用法:
```
python scan.py ip [-o nt] [-p 80,81-85,...]
```
ip 可以是 单个ip、CIDR 或者 192.168.0.0-255 这种形式
-o 选项 n 就是使用 nbns 探测主机名，t 就是探测 TCP端口，默认是同时探测
-p 指定 TCP 的端口

## 例子:
```
python scan.py 10.19.38.0/24
```
扫描 10.19.38.0/24 的默认端口，并获取主机名

```
python scan.py 10.19.38.0/24 -o n
```
获取 10.19.38.0/24 的主机名，不扫描 TCP 端口

```
python scan.py 10.19.38.0/24 -p 22,23-25
```
扫描 10.19.38.0/24 的 TCP 22,23,24,25 端口，获取主机名

## 返回格式:
- 不认识的 banner 就直接打印出来
- HTTP 会把 Server、Location，<title> 打印出来
- +Vulnerable+
```
[*]202.115.*.*
   21   220 MikroTik FTP server (MikroTik 5.20) ready\r\n
   22   SSH-2.0-ROSSSH\r\n
   23    #'
   80   HTTP/1.1 200 OK Title: RouterOS router configuration page
   445   +Vulnerable+ MS 17-010    Windows 7 Professional 7601 Service Pack 1|Windows 7 Professional 6.1|
```