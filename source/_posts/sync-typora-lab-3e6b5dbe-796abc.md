---
title: "实验1模板"
date: 2026-11-13 19:08:04
categories:
  - "知识点"
  - "实验"
tags: []
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-lab/实验1_模板.md#0 -->
## 实验1：CentOS 7安装、网络配置、远程访问



**实验目的**

> 1、掌握Linux虚拟机的安装方法；
>
> 2、掌握Linux网络配置方法；
>
> 3、掌握远程访问Linux系统的方式。



### 1.实验要求

> 任务1：安装虚拟机；（实验过程可以省略）
> 任务2：安装CentOS 7（或8）（建议：最小化安装）； （安装成功后的截图即可）
>
> 任务3：配置网络为NAT模式，实现物理机与虚拟机的相互访问。（要求：IP地址段为学号后两位，即192.168.学号.**）
> （1）	虚拟机配置为动态IP地址，Ping物理主机测试连通性。
>
>
> （2）	虚拟机配置为静态IP地址，Ping物理主机测试连通性。192.168.xx.0-255
>
> 任务4：Windows主机上安装Xhell，实现远程访问CentOS 7系统。
>
> 任务5：两台Linux相互登陆（需克隆出另一台CentOS7)。参考《跟阿铭学Linux  第3版.pdf》P45，3.3节 两台Linux相互登陆。  
>
> 任务6：SSH密码爆破；SSH密钥连接
>
> 任务7：完成后，虚拟机“拍快照”保存当前状态。（实验过程可以省略）
>
> **拓展任务8：**
>
> SSH密钥泄露靶场，参考《ssh-私钥泄露.pdf》，渗透测试报告，以pdf形式提交

### 2.实验过程

#### 2.1 在VMware中安装centos 7

首先下载vmeare,打开

![image-20260905164701593](/pwn-notes/images/notes/image-20260905164701593.png)

之后去寻找相关镜像，这里在阿里云选择centos7镜像。

![image-20260905164919557](/pwn-notes/images/notes/image-20260905164919557.png)

这是下载到本机的镜像文件，之后新建一路推荐。但是在最后需要选择镜像文件。

![image-20260905165123380](/pwn-notes/images/notes/image-20260905165123380.png)

还有在配置虚拟机时需要打开网络配置，之后最小化安装，之后配置好重启。

![image-20260905165614120](/pwn-notes/images/notes/image-20260905165614120.png)

这是登录界面，之后输入账号密码



![image-20260905165712441](/pwn-notes/images/notes/image-20260905165712441.png)



登陆成功

#### 2.2 配置网络为NAT模式，实现物理机与虚拟机的相互访问。

##### 2.2.1更换yum源

但是首先修改相关的配置文件需要vim工具，但是里面没有。

![image-20260905171307228](/pwn-notes/images/notes/image-20260905171307228.png)

那么就使用yum下载相关工具



![image-20260905171415671](/pwn-notes/images/notes/image-20260905171415671.png)

可以看到会出现问题，因为原本centoc的yum源在国外，访问受限，于是修改相关的配置文件，改成国内的源。

这里我直接问豆包，找到一条可以配置成功的，就直接把原来的配置文件全部替换掉。

1.首先备份原来的文件，以便可以恢复

```bash
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bad
```

2.直接替换源文件

```bash
cat > /etc/yum.repos.d/CentOS-Base.repo <<'EOF'
[base]
name=CentOS‑7‑Base‑Ali‑Vault
baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/centos/RPM-GPG-KEY-CentOS-7

[updates]
name=CentOS‑7‑Updates‑Ali‑Vault
baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/centos/RPM-GPG-KEY-CentOS-7

[extras]
name=CentOS‑7‑Extras‑Ali‑Vault
baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/extras/$basearch/
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/centos/RPM-GPG-KEY-CentOS-7

[centosplus]
name=CentOS‑7‑Plus‑Ali‑Vault
baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=https://mirrors.aliyun.com/centos/RPM-GPG-KEY-CentOS-7
EOF

```

![image-20260905173649439](/pwn-notes/images/notes/image-20260905173649439.png)



3.清理缓存重建

```bash
yum clean all
yum makecache
```

![image-20260905174312856](/pwn-notes/images/notes/image-20260905174312856.png)

之后测试yum

![image-20260905191816058](/pwn-notes/images/notes/image-20260905191816058.png)

可以看到此时yum源已经换成aliyun了

##### 2.2.2虚拟机配置为动态IP地址，Ping物理主机测试连通性。

我的学号后两位是21，所以是192.168.21.*

首先更改虚拟机网络配置为net模式

关闭虚拟机

![image-20260905195051829](/pwn-notes/images/notes/image-20260905195051829.png)

编辑——>虚拟网络编辑器，点击更改设置

![image-20260905195439861](/pwn-notes/images/notes/image-20260905195439861.png)

接下来更改子网ip，确定完之后再点击NAT设置，看到网关ip已经改了。

![image-20260905200022271](/pwn-notes/images/notes/image-20260905200022271.png)



启动DHCP。DHCP:DHCP 服务就是 VMware 里的虚拟 DHCP 服务器，虚拟机动态 IP 模式开机，它就自动给 CentOS 分配同网段 IP 地址。

![image-20260906100555649](/pwn-notes/images/notes/image-20260906100555649.png)

在这里可以看到分配的动态IP的范围，并且DHCP已经启用。

在物理windows主机终端查看虚拟网卡地址：输入

```shell
ipconfig
```

![image-20260906101123954](/pwn-notes/images/notes/image-20260906101123954.png)

看到是192.168.21.1

###### 1.修改网卡配置文件

```shell
vi /etc/sysconfig/network-scripts/ifcfg-ens33
```



![image-20260906101640061](/pwn-notes/images/notes/image-20260906101640061.png)

可以看到相关的已经开启。接下来输入:wq保存并退出。

###### 2.重启网络：

```shell
systemctl restart network
```

###### 3.查看获取到的 IP 地址

```shell
ip addr
```

![image-20260906102445125](/pwn-notes/images/notes/image-20260906102445125.png)

可以看到分配到的就是192.168.21.128

现在可以pingwindows主机，就是192.168.21.1

![image-20260906102746683](/pwn-notes/images/notes/image-20260906102746683.png)

虚拟机已经可以和主机ping通。

接下来测试主机Ping虚拟机

![image-20260906103206395](/pwn-notes/images/notes/image-20260906103206395.png)

通信成功。

##### 2.2.3 虚拟机配置为静态IP地址，Ping物理主机测试连通性。

###### 1.编辑网卡配置文件

```shell
vi /etc/sysconfig/network-scripts/ifcfg-ens33
```

![image-20260906103602763](/pwn-notes/images/notes/image-20260906103602763.png)

将DHCP改成static,然后再后面追加相关的ip设置。

![image-20260906103837561](/pwn-notes/images/notes/image-20260906103837561.png)

这里的静态ip配置的是192.168.21.111

###### 2.重启网络服务

```shell
systemctl restart network
```

![image-20260906104429008](/pwn-notes/images/notes/image-20260906104429008.png)

可以看到再次查看ip就变成了我们设置的。

###### 3.连通测试

虚拟机连接主机

![image-20260906104818501](/pwn-notes/images/notes/image-20260906104818501.png)

主机连接虚拟机

![image-20260906104908375](/pwn-notes/images/notes/image-20260906104908375.png)

##### 2.3远程访问虚拟机

MobaXterm远程连接

首先需要知道虚拟机的ip地址，还有一开始设置的密码，我设置的是1

![image-20260906105400264](/pwn-notes/images/notes/image-20260906105400264.png)

比如这里就是192.168.21.111

那么这个时候打开软件，点击session

![image-20260906105613318](/pwn-notes/images/notes/image-20260906105613318.png)

点击SSH接着填入虚拟机地址以及root

![image-20260906105737868](/pwn-notes/images/notes/image-20260906105737868.png)

点击ok之后，输入密码之后，就可以了。

![image-20260906110330017](/pwn-notes/images/notes/image-20260906110330017.png)

##### 2.4两台Linux相互登陆

这里用另一台kali机

![image-20260906111834938](/pwn-notes/images/notes/image-20260906111834938.png)

地址是192.168.21.129，centos是192.168.21.111

###### 1.检查ssh登录状态

```shell
systemctl status sshd
```

![image-20260906112657106](/pwn-notes/images/notes/image-20260906112657106.png)

可以看到cenosssh服务已经启动了

接下来查看kali

```
sudo systemctl status ssh
sudo systemctl start ssh
```

![image-20260906113200023](/pwn-notes/images/notes/image-20260906113200023.png)

没有启动

接下来启动

```
sudo systemctl start ssh
```

![image-20260906113325529](/pwn-notes/images/notes/image-20260906113325529.png)

也启动成功。

###### 2.1 CentOS 登录 Kali



```
ssh kali@192.168.21.129
```

接下来输入kali的密码，之后yes就可以

![image-20260906113629944](/pwn-notes/images/notes/image-20260906113629944.png)

###### 2.2 Kali 登录 CentOS



```
ssh root@192.168.21.111
```

![image-20260906113943944](/pwn-notes/images/notes/image-20260906113943944.png)

在登陆的时候，centos要输入exit退出kali登录。



##### 2.5.SSH密码爆破；SSH密钥连接

###### 2.5.1 ssh密钥连接

1-客户端生成密钥对

```shell
ssh-keygen
```

![image-20260906165719494](/pwn-notes/images/notes/image-20260906165719494.png)

enter继续

生成两个文件![image-20260906165932863](/pwn-notes/images/notes/image-20260906165932863.png)

上面的是私钥，下面的是公钥。

2.将公钥发送到kali机器，这样在centos上就可以登录kali。

```shell
ssh-copy-id kali@192.168.21.129
```

![image-20260906171004467](/pwn-notes/images/notes/image-20260906171004467.png)

3、测试免密登录

```shell
ssh kali@192.168.21.129
```

![image-20260906171113930](/pwn-notes/images/notes/image-20260906171113930.png)

可以看到登陆成功。

###### 2.5.2.SSH密码爆破

使用kali自带的hydra工具。

首先分别创建用户名字典和密码字典，我这里其中包含真正的密码和用户名

![image-20260906171746013](/pwn-notes/images/notes/image-20260906171746013.png)

![image-20260906171821367](/pwn-notes/images/notes/image-20260906171821367.png)

然后使用命令，去登录centos7,但是centos7开启了密钥登录，如果还需要继续进行密码爆破需要将密钥登录取消换成密码登录。

1.清理残留公钥

```shell
rm -rf /root/.ssh/authorized_keys
```

2.修改 ssh 配置，开启密码登录

```shell
vi /etc/ssh/sshd_config
```

将前面的注释去掉，保存退出

![image-20260906173329250](/pwn-notes/images/notes/image-20260906173329250.png)

![image-20260906173635045](/pwn-notes/images/notes/image-20260906173635045.png)

3.重启 sshd 服务生效

```shell
systemctl restart sshd
```

![image-20260906173956263](/pwn-notes/images/notes/image-20260906173956263.png)

可以看到这个时候登录就需要密码，这个时候再次进行密码爆破。额，原来是记错密码了，一开始的密码字典没有，或许刚才的ssh文件修改是多余的，又或者不是。

![image-20260906175004260](/pwn-notes/images/notes/image-20260906175004260.png)

这里可以看到账户是root

密码是1

##### 2.6 为当前虚拟机拍摄快照

![image-20260906175522296](/pwn-notes/images/notes/image-20260906175522296.png)

![image-20260906175556123](/pwn-notes/images/notes/image-20260906175556123.png)

##### 2.7  SSH密钥泄露靶场

![image-20260906181710234](/pwn-notes/images/notes/image-20260906181710234.png)

首先打开之后发现需要登录，需要账号密码，这个时候可以打开kali扫一下当前靶机ip

###### 1.扫描同网段ip，查找靶机

一直扫不出来，发现靶机直接是桥接模式，需要换成和kali一样的nat模式

![image-20260906184426847](/pwn-notes/images/notes/image-20260906184426847.png)

输入

```shell
sudo netdiscover -r 192.168.21.129/24
```

这次终于发现130了

![image-20260906184633404](/pwn-notes/images/notes/image-20260906184633404.png)

###### 2.nmap扫描开放端口

```shell
nmap -sV 192.168.21.130
```

![image-20260906185016066](/pwn-notes/images/notes/image-20260906185016066.png)

可以看到开放了3个端口

访问80

![image-20260906185223214](/pwn-notes/images/notes/image-20260906185223214.png)

访问31337

![image-20260906185342825](/pwn-notes/images/notes/image-20260906185342825.png)

都没有什么东西

###### 3.扫描端口目录

```shell
dirb http://192.168.21.130:31337 /usr/share/wordlists/dirb/common.txt
```

![image-20260906192141131](/pwn-notes/images/notes/image-20260906192141131.png)

扫描出来5个

1.bash_history

![image-20260906192312430](/pwn-notes/images/notes/image-20260906192312430.png)

2.bashrc

![image-20260906192656269](/pwn-notes/images/notes/image-20260906192656269.png)

AI说是本地shell配置文件没啥用，我也看不懂

3.profile

![image-20260906192902751](/pwn-notes/images/notes/image-20260906192902751.png)

也是配置文件

4.ssh

![image-20260906193337750](/pwn-notes/images/notes/image-20260906193337750.png)

这个好像是ssh远程登录需要的。

那么可以查看这三个

4.1id_rsa

![image-20260906194143761](/pwn-notes/images/notes/image-20260906194143761.png)

看不懂，ai说是加密的rsa私钥。

![image-20260906194349102](/pwn-notes/images/notes/image-20260906194349102.png)

kali自带工具可以破解

![image-20260906194953344](/pwn-notes/images/notes/image-20260906194953344.png)

starwars

4.2 authorized_keys



![image-20260906195334268](/pwn-notes/images/notes/image-20260906195334268.png)

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzG6cWl499ZGW0PV+tRaOLguT8+lso8zbSLCzgiBYkX/xnoZx0fneSfi93gdh4ynVjs2sgZ2HaRWA05EGR7e3IetSP53NTxk5QrLHEGZQFLId3QMMi74ebGBpPkKg/QzwRxCrKgqL1b2+EYz68Y9InRAZoq8wYTLdoUVa2wOiJv0PfrlQ4e9nh29J7yPgXmVAsy5ZvmpBp5FL76y1lUblGUuftCfddh2IahevizLlVipuSQGFqRZOdA5xnxbsNO4QbFUhjIlA5RrAs814LuA9t2CiAzHXxjsVW8/R/eD8K22TO7XEQscQjaSl/R4Cr1kNtUwCljpmpjt/Q4DJmExOR simon@covfefe

```

最后是用户名

simon，而密码是starwars

4.3 id_rsa.pub

和上面的一样

![image-20260906195704814](/pwn-notes/images/notes/image-20260906195704814.png)

4.4 尝试登录

![image-20260906195904747](/pwn-notes/images/notes/image-20260906195904747.png)

登陆成功

5.robots.txt

![image-20260906193735164](/pwn-notes/images/notes/image-20260906193735164.png)

依次尝试可以发现flag

![image-20260906193718283](/pwn-notes/images/notes/image-20260906193718283.png)

###### 4.ssh远程登录

前面已经知道了id_rsa文件，放进kali中

![image-20260906205525941](/pwn-notes/images/notes/image-20260906205525941.png)

原来那个密码是这里的密码，在知道用户名之后，使用这个密码也成功登陆了，或许是碰巧。

john工具：

![image-20260906210103751](/pwn-notes/images/notes/image-20260906210103751.png)

原来并没有解出私钥，而是这个文件的密码

所以，知道密码就进行远程登录

1.设置私钥权限

```shell
chmod 600 id_rsa
```

![image-20260906210428181](/pwn-notes/images/notes/image-20260906210428181.png)

2.SSH 密钥登录命令

```shell
ssh -i id_rsa simon@192.168.21.130
```

中间输入密码是：starwars



![image-20260906210940336](/pwn-notes/images/notes/image-20260906210940336.png)

登陆成功

### 3.实验小结

> 可以使用文字描述完成实验后的收获，或者主要学会的命令等等。

知道远程ssh连接的主要流程，和各个部分需要的文件。

<!-- sync-hash: e0feb2cacdff6fd9a4738b3c4fa0a875b75eb898904e19926bfabdc68cce2bbd -->
