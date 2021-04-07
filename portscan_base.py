#coding:utf-8

import logging
import os
logger = logging.getLogger(__name__)
from scapy.all import *
import threading
from queue import Queue
import nmap
from random import randint
import time
import psutil
import signal
stop=0
class Portscan():

    def __init__(self):
        self.result = []
        self.tcp_ports=[]
        self.udp_ports=[]
        global stop
        stop = 0
        self.q = Queue()
        self.ip=''

    def run(self, ip, protocol="tcp", tcp_start=None, tcp_end=None, udp_start=1, udp_end=1000, connect="1"):
        # connect=1表示进行tcp半连接扫描
        global stop
        try:
            thread_num=128
            logger.info("[*]开始端口扫描...")
            self.log(log="[*]开始端口扫描...", current=0, total=100)
            logger.info("[*]检测IP是否连接...")
            self.log(log="[*]检测IP是否连接...", current=0, total=100)
            if Portscan.test_ip(ip):
                logger.info("[*]检测IP连接成功...")
                self.log(log="[*]检测IP连接成功...", current=1, total=100)
                logger.info("初始化扫描组件...")
                self.log(log="[*]初始化扫描组件...", current=3, total=100)
                self.ip=ip
                logger.info("扫描组件初始化成功...")
                self.log(log="[*]扫描组件初始化成功...", current=10, total=100)
                #tcp扫描
                if 'tcp' in str(protocol).lower():
                    #tcp半连接扫描
                    if '1' in connect:
                        # TCP半连接扫描
                        logger.info("正在进行tcp协议半连接扫描...")
                        if 'udp' in str(protocol).lower():
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=25, total=100)
                        else:
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=60, total=100)
                    else:
                        #TCP全连接扫描
                        logger.info("正在进行tcp协议全连接扫描...")
                        if 'udp' in str(protocol).lower():
                            self.log(log="[*]正在进行tcp协议全连接扫描...", current=25, total=100)
                        else:
                            self.log(log="[*]正在进行tcp协议全连接扫描...", current=60, total=100)
                    if tcp_start and tcp_end:
                        for i in range(int(tcp_start), int(tcp_end)+1):
                            self.q.put(i)
                        my_threads = [threading.Thread(target=self.tcp_scan, args=(connect)) for i in range(thread_num)]
                    else:
                        for i in range(1, 1000):
                            self.q.put(i)
                        my_threads = [threading.Thread(target=self.tcp_scan, args=(connect)) for i in range(thread_num)]

                    logger.info("线程初始化完毕...")
                    for t in my_threads:
                        t.start()
                    for t in my_threads:
                        t.join()
                    if stop == 1:
                        logger.info("停止扫描")
                        self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                        return {'status': 2, 'msg': "停止扫描"}
                    logger.info("tcp协议扫描完成...")
                    if 'udp' in str(protocol).lower():
                        self.log(log="[*]tcp协议扫描完成...", current=50, total=100)
                    else:
                        self.log(log="[*]tcp协议扫描完成...", current=100, total=100)

                #udp扫描
                if 'udp' in str(protocol).lower():
                    nm = nmap.PortScanner()
                    logger.info("正在进行udp协议扫描...")
                    if 'tcp' in str(protocol).lower():
                        self.log(log="[*]正在进行udp协议扫描...", current=60, total=100)
                    else:
                        self.log(log="[*]正在进行udp协议扫描...", current=50, total=100)
                    if udp_start and udp_end:
                        result = nm.scan(hosts=ip, arguments='-sU -p ' + str(udp_start) + "-" + str(udp_end))
                    else:
                        result = nm.scan(hosts=ip, arguments='-sU --top-ports 1000')
                    if stop == 1:
                        logger.info("停止扫描")
                        self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                        return {'status': 2, 'msg': "停止扫描"}
                    ret = dict(result)['scan'][ip]
                    if 'udp' in ret:
                        udp_port = ret['udp']
                    else:
                        udp_port = []
                    logger.info("udp协议扫描完成...")
                    self.log(log="[*]udp协议扫描完成...", current=100, total=100)
                    self.result = self.result + [
                        {"ip": ip, "port": str(key), "protocol": "UDP", "service": str(udp_port[key]['name']),
                         "state": str(udp_port[key]['state'])} for key in udp_port]

                logger.info(self.result)
                self.log(log="[*]扫描已完成", Done=True, current=100, total=100)
                return {'status': 1, 'data': self.result, 'msg': "端口扫描成功"}
            else:
                logger.info("IP连接失败")
                self.log(log="[*]IP连接失败", current=0, total=100)
                self.log(log="[*]扫描失败", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "IP连接失败"}

        except Exception as e:
            logger.error(e)
            if stop == 1:
                logger.info("停止扫描")
                self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "停止扫描"}
            else:
                logger.info("端口扫描失败")
                self.log(log="[*]端口扫描失败", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "端口扫描失败"}


    @staticmethod
    def stop():
        #停止检测.
        try:
            # pids = psutil.pids()
            # for pid in pids:
            #     p = psutil.Process(pid)
            #     if "nmap" in p.name():
            #         os.kill(pid, signal.SIGKILL)
            global stop
            stop = 1
            return {'status': 0, 'data': '', 'msg': '停止成功'}
        except Exception as e:
            # print(e)
            return {'status': 1, 'data': '', 'msg': '停止失败'}


    def log(self, log, Done=False, current=None, total=None):
        pass

    #静态方法，可无须实例化使用
    @staticmethod
    def test_ip(ip):
        """测试IP
        测试是否能够ping通
        """
        backinfo = os.system('ping -c 1 -w 10 %s' % ip)
        if not backinfo:
            return True
        else:
            return False

    #tcp端口扫描
    def tcp_scan(self,connect="1"):
        #tcp半连接扫描
        global stop
        while not self.q.empty() and stop==0:
            port = self.q.get()
            packet = IP(dst=self.ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=2, verbose=0)
            if not response:
                # print('[+]TCP SYN端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
                pass
            elif response.haslayer(TCP):
                if response[TCP].flags == 'SA':
                    if "1" in connect:
                        # 半连接
                        self.tcp_ports.append(port)
                        nm=nmap.PortScanner()
                        res = nm.scan(hosts=self.ip, arguments='-sS -p ' +str(port))
                        ret = dict(res)['scan'][self.ip]
                        if 'tcp' in ret:
                            tcp_port = ret['tcp']
                        else:
                            tcp_port = []
                        self.result = self.result + [
                            {"ip": self.ip, "port": str(key), "protocol": "TCP", "service": str(tcp_port[key]['name']),
                             "state": str(tcp_port[key]['state'])} for key in tcp_port]
                        # print('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                    else:
                        # 全连接
                        packet2 = IP(dst=self.ip) / TCP(dport=port, flags='A', ack=(response[TCP].seq + 1))
                        response2 = sr1(packet2, timeout=2, verbose=0)
                        if response2:
                            self.tcp_ports.append(port)
                            nm = nmap.PortScanner()
                            res = nm.scan(hosts=self.ip, arguments='-sT -p ' + str(port))
                            # print('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                            ret = dict(res)['scan'][self.ip]
                            if 'tcp' in ret:
                                tcp_port = ret['tcp']
                            else:
                                tcp_port = []
                            self.result = self.result + [
                                {"ip": self.ip, "port": str(key), "protocol": "TCP", "service": str(tcp_port[key]['name']),
                                 "state": str(tcp_port[key]['state'])} for key in tcp_port]

                elif response[TCP].flags == 'RA':
                    # print('[+]TCP SYN端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
                    pass
        return True

    #udp端口扫描
    def udp_scan(self):
        while not self.q.empty():
            port = self.q.get()
            packet = IP(dst=self.ip) / UDP(dport=port,sport=randint(1,65535))
            response = sr1(packet, timeout=2, verbose=0)
            time.sleep(1)
            # 是否返回icmp
            if response is None:
                self.udp_ports.append(port)
            else:
                # print('[+]UDP端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
                pass
        return True

# if __name__ == '__main__':
#     start_time = time.time()
#     scan = Portscan()
#     scan.run(ip='172.16.20.23', protocol='udp', tcp_start=1, tcp_end=65535,udp_start=1,udp_end=100,connect="1")
#     end_time=time.time()
#     print(scan.result)
#     print('spend time:',end_time-start_time,'s')

