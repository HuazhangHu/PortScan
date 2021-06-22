#coding:utf-8
#portscan test
import logging
import os
logger = logging.getLogger(__name__)
from scapy.all import *
import threading
from queue import Queue
import nmap
from random import randint
import time

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
        try:
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
                # nm=nmap.PortScanner()
                logger.info("扫描组件初始化成功...")
                self.log(log="[*]扫描组件初始化成功...", current=10, total=100)
                #tcp扫描
                if 'tcp' in str(protocol).lower():
                    print("正在进行tcp协议扫描...")
                    #tcp半连接扫描
                    if '1' in connect:
                        # TCP半连接扫描
                        print("正在进行tco协议半连接扫描")
                        logger.info("正在进行tcp协议半连接扫描...")
                        self.log(log="[*]正在进行tcp协议半连接扫描...")
                        if 'udp' in str(protocol).lower():
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=25, total=100)
                        else:
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=60, total=100)
                        if tcp_start and tcp_end:
                            for i in range(tcp_start, tcp_end+1):
                                self.q.put(i)
                            my_threads = [threading.Thread(target=self.tcp_scan,args=(connect)) for i in range(2048)]
                        else:
                            for i in range(1, 1001):
                                self.q.put(i)
                            my_threads = [threading.Thread(target=self.tcp_scan, args=(connect)) for i in range(2048)]
                        for t in my_threads:
                            t.start()
                        for t in my_threads:
                            t.join()
                        # res=nm.scan(hosts=ip,arguments='-sS -p '+",".join(str(i) for i in self.tcp_ports ))

                    else:
                        #TCP全连接扫描
                        print("正在进行tco协议全连接扫描")
                        logger.info("正在进行tcp协议全连接扫描...")
                        self.log(log="[*]正在进行tcp协议全连接扫描...")
                        if 'udp' in str(protocol).lower():
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=25, total=100)
                        else:
                            self.log(log="[*]正在进行tcp协议半连接扫描...", current=60, total=100)
                        if tcp_start and tcp_end:
                            for i in range(int(tcp_start), int(tcp_end)):
                                self.q.put(i)
                            my_threads = [threading.Thread(target=self.tcp_scan, args=(connect)) for i in range(2048)]
                        else:
                            for i in range(1, 1000):
                                self.q.put(i)
                            my_threads = [threading.Thread(target=self.tcp_scan, args=(connect)) for i in range(2048)]
                        for t in my_threads:
                            t.start()
                        for t in my_threads:
                            t.join()
                        # res = nm.scan(hosts=ip, arguments='-sT -p ' + ",".join(str(i) for i in self.tcp_ports))

                    # ret = dict(res)['scan'][ip]
                    # if 'tcp' in ret:
                    #     tcp_port = ret['tcp']
                    # else:
                    #     tcp_port = []
                    # self.result = self.result + [
                    #     {"ip": ip, "port": str(key), "protocol": "TCP", "service": str(tcp_port[key]['name']),
                    #      "state": str(tcp_port[key]['state'])} for key in tcp_port]
                    logger.info("tcp协议扫描完成...")
                    if 'udp' in str(protocol).lower():
                        self.log(log="[*]tcp协议扫描完成...", current=50, total=100)
                    else:
                        self.log(log="[*]tcp协议扫描完成...", current=100, total=100)

                #udp扫描
                if 'udp' in str(protocol).lower():
                    print("正在进行udp协议扫描...")
                    if 'tcp' in str(protocol).lower():
                        self.log(log="[*]正在进行udp协议扫描...", current=60, total=100)
                    else:
                        self.log(log="[*]正在进行udp协议扫描...", current=50, total=100)
                    if udp_start and udp_end:
                        for i in range(int(udp_start), int(udp_end)):
                            self.q.put(i)
                        my_threads = [threading.Thread(target=self.udp_scan) for i in range(8)]
                    else:
                        for i in range(1, 100):
                            self.q.put(i)
                        my_threads = [threading.Thread(target=self.udp_scan) for i in range(8)]
                    for t in my_threads:
                        t.start()
                    for t in my_threads:
                        t.join()
                    # res = nm.scan(hosts=ip, arguments='-sU -p ' + ",".join(str(i) for i in self.udp_ports))
                    # ret = dict(res)['scan'][ip]
                    # if 'udp' in ret:
                    #     udp_port = ret['udp']
                    # else:
                    #     udp_port = []
                    # self.result = self.result + [{"ip": ip, "port": str(key), "protocol": "UDP", "service": str(udp_port[key]['name']),"state": str(udp_port[key]['state'])} for key in udp_port]
                    #
                    # logger.info("udp协议扫描完成...")
                    # self.log(log="[*]udp协议扫描完成...", current=100, total=100)
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
            global stop
            if stop == 1:
                logger.info("停止扫描")
                self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "停止扫描"}
            else:
                logger.info("端口扫描失败")
                self.log(log="[*]端口扫描失败", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "端口扫描失败"}


    def log(self, log, Done=False, current=None, total=None):
        pass

    #静态方法，可无须实例化使用
    @staticmethod
    def test_ip(ip):
        """测试IP
        测试是否能够ping通
        """
        backinfo = os.system('ping -c 1 -w 10 %s' % ip)
        #ping 通为0，否则为1
        #！
        if backinfo:
            return True
        else:
            return False

    #tcp端口扫描
    def tcp_scan(self,connect="1"):
        #tcp半连接扫描
        while not self.q.empty():
            port = self.q.get()
            # SYN扫描,sr1返回一个应答包
            packet = IP(dst=self.ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=2, verbose=0)
            if not response:
                print('[+]TCP SYN端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
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
                        print('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                    else:
                        # 全连接
                        packet2 = IP(dst=self.ip) / TCP(dport=port, flags='A', ack=(response[TCP].seq + 1))
                        response2 = sr1(packet2, timeout=2, verbose=0)
                        if response2:
                            self.tcp_ports.append(port)
                            nm = nmap.PortScanner()
                            res = nm.scan(hosts=self.ip, arguments='-sT -p ' + str(port))
                            print('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                            ret = dict(res)['scan'][self.ip]
                            if 'tcp' in ret:
                                tcp_port = ret['tcp']
                            else:
                                tcp_port = []
                            self.result = self.result + [
                                {"ip": self.ip, "port": str(key), "protocol": "TCP", "service": str(tcp_port[key]['name']),
                                 "state": str(tcp_port[key]['state'])} for key in tcp_port]

                elif response[TCP].flags == 'RA':
                    # RST
                    print('[+]TCP SYN端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
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
                nm=nmap.PortScanner()
                res = nm.scan(hosts=self.ip, arguments='-sU -p ' +str(port))
                ret = dict(res)['scan'][self.ip]
                if 'udp' in ret:
                    udp_port = ret['udp']
                else:
                    udp_port = []
                self.result = self.result + [
                    {"ip": self.ip, "port": str(key), "protocol": "UDP", "service": str(udp_port[key]['name']),
                     "state": str(udp_port[key]['state'])} for key in udp_port]
                print('[+]UDP端口扫描 %s %d \033[1;32;40m OPEN \033[0m' % (self.ip, port))
                self.udp_ports.append(port)
            else:
                print('[+]UDP端口扫描 %s %d \033[91m Closed \033[0m' % (self.ip, port))
        return True


if __name__ == '__main__':
    start_time = time.time()
    scan = Portscan()
    scan.run(ip='172.16.20.23', protocol='udp', tcp_start=1, tcp_end=65535,udp_start=1,udp_end=100,connect="1")
    end_time=time.time()
    print(scan.result)
    print('spend time:',end_time-start_time,'s')

