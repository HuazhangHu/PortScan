#coding:utf-8
'''
itb 端口与服务扫描 0421 9:00
'''

from random import randint
import threading
from queue import Queue

import nmap
from scapy.layers.inet import TCP, IP, UDP
from scapy.all import *
from libnmap.process import NmapProcess
from router import logger
from app.system.utils.ncConfig import NCConfig
# import logging
#
# logger = logging.getLogger(__name__)
stop=0

class Portscan():

    def __init__(self):
        global stop
        stop = 0
        self.result = []
        self.ip=''
        self.connect='1'
        self.thread_num=128#线程数
        self.q = Queue()
        self.tcp_total=0
        self.udp_total=0
        self.udp_done=Queue()
        self.tcp_done=Queue()
        self.iface=''
        self.sleep=3 #log打印时间间隔

    def run(self, ip, src, iface, protocol="tcp", tcp_start=None, tcp_end=None, udp_start=1, udp_end=1000, connect="1"):
        '''
        Args:
            ip: string 扫描的ip地址
            src:string 源ip地址
            iface:string 网卡名称
            protocol: string  'tcp' ,'udp'
            tcp_start: integer
            tcp_end: integer
            udp_start: integer
            udp_end: interger
            connect: char '1' or '0'
        Returns:
            json格式 {'status':'0' 停止 '1' 成功 '2' 失败
                          'data': list[dict{'ip','port','protocol','server'} , 'msg'}
        '''
        self.ip = ip
        self.connect=connect
        start_time=time.time()
        self.iface=iface
        self.log(log="[*]开始端口扫描...")
        self.log(log="[*]检测IP是否连接...")
        if not src or not Portscan.test_ip(src,ip) or not self.iface :
            logger.info("IP连接失败...")
            self.log(log="[*]IP连接失败", current=0, total=100)
            self.log(log="[*]扫描失败", Done=True, current=0, total=100)
            return {'status': 2, 'msg': "IP连接失败"}
        logger.info("[*]检测IP连接成功...")
        self.log(log="[*]检测IP连接成功...")
        thread_pool=[]
        try:
            flag=0
            if 'tcp' in str(protocol).lower():
                if '1' in self.connect:
                    logger.info("正在进行tcp协议半连接扫描...")
                    self.log(log="[*]正在进行tcp协议半连接扫描...")
                else:
                    logger.info("正在进行tcp协议全连接扫描...")
                    self.log(log="[*]正在进行tcp协议全连接扫描...")
                thread_tcp = threading.Thread(target=self.tcp_scan, args=(tcp_start, tcp_end))
                thread_pool.append(thread_tcp)
                if 'udp' not in str(protocol).lower():
                    flag=1

            if 'udp' in str(protocol).lower():
                logger.info("正在进行udp协议扫描...")
                self.log(log="[*]正在进行udp协议扫描...")
                thread_udp = threading.Thread(target=self.udp_scan, args=(udp_start, udp_end))
                thread_pool.append(thread_udp)
                if 'tcp' not in str(protocol).lower():
                    flag=2

            if 'tcp' in str(protocol).lower() and 'udp' in str(protocol).lower():
                flag=3

            thread_log = threading.Thread(target=self.log_print,args=(flag,))
            thread_pool.append(thread_log)

            for t in thread_pool:
                t.start()
            for t in thread_pool:
                t.join()

            if stop == 1:
                logger.info("停止扫描")
                self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                return {'status': 2, 'msg': "停止扫描"}
            end_time=time.time()
            self.log(log="[*]扫描已完成,共花费{0} s".format(end_time-start_time), Done=True, current=100, total=100)
            logger.info(self.result)
            return {'status': 1, 'data': self.result, 'msg': "端口扫描成功"}

        except Exception as e:
            logger.error("端口扫描失败%s" % e)
            self.log(log="[*]端口扫描失败", Done=True, current=0, total=100)
            return {'status': 2, 'msg': "端口扫描失败"}

    @staticmethod
    def stop():
        """停止检测.
        """
        global stop
        stop = 1
        return {'status': 0, 'data': '', 'msg': '停止成功'}

    def log(self, log, Done=False, current=None, total=None):
        pass

    def log_print(self, flag):
        '''
        :param flag:integer 1:tcp 2:udp 3: tcp and udp 0:error
        :return:
        '''

        if flag == 1:  # 只进行tcp扫描

            while stop==0 and self.tcp_done.qsize()!=self.tcp_total:
                    self.log(log='[*]TCP端口扫描完成%d/%d' % (self.tcp_done.qsize(),self.tcp_total), current=self.tcp_done.qsize(),total=self.tcp_total)
                    time.sleep(self.sleep)

        elif flag == 2:  # 只进行udp扫描
            old=0
            while stop==0:
                if not self.udp_done.empty():
                    current=self.udp_done.get()
                    if current>=old:
                        self.log(log='[*]UDP端口扫描完成%d/%d' % (current,self.udp_total), current=current,total=self.udp_total)
                        old=current
                        time.sleep(self.sleep)
                    if current == self.udp_total:
                        break

        elif flag == 3: # tcp,udp同时进行
            old=0
            while stop==0:
                if not self.udp_done.empty():
                    tcp_current=self.tcp_done.qsize()
                    udp_current=self.udp_done.get()
                    current=tcp_current+udp_current
                    if current>=old:
                        self.log(log='[*]端口扫描完成%d/%d' % (current,self.tcp_total + self.udp_total),current=current,total=self.tcp_total + self.udp_total)
                        old=current
                    if udp_current==self.udp_total and tcp_current==self.tcp_total:
                        break
        else:
            return

    @staticmethod
    def test_ip(src,ip):
        '''
        测试ip是否能够ping通
        :param ip:
        :return: Bool True能够ping通 False 不能ping通
        '''
        backinfo = os.system('ping -I {0} -c 1 -w 10 {1}' .format(src,ip))
        if not backinfo:
            return True
        else:
            return False

    def tcp_scan(self, tcp_start, tcp_end):
        '''多线程tcp端口扫描函数
        :param tcp_start:
        :param tcp_end:
        :return:
        '''
        self.tcp_done = Queue()
        if tcp_start and tcp_end:
            #扫描指定端口区间
            self.tcp_total = int(tcp_end) + 1 - int(tcp_start)
            for i in range(int(tcp_start),int(tcp_end)+1):
                self.q.put(i)
        else:
            self.log('[*]正在扫描常见TCP端口')
            #扫描常见top1000端口
            for i in [7, 9, 11, 13, 15, 17, 18, 19, 20, 21, 22, 23, 25, 31, 37, 39, 41, 42, 43, 58, 59, 63, 69, 70, 79, 80, 88, 101, 102, 107, 109, 110, 111, 113, 117, 119, 121, 135, 138, 139, 143, 146, 158, 170, 179, 194, 213, 220, 389, 406, 411, 421, 443, 445, 456, 464, 512, 513, 514, 515, 517, 518, 520, 525, 526, 530, 531, 532, 533, 540, 543, 544, 550, 554, 555, 556, 560, 561, 636, 666, 749, 750, 911, 989, 990, 992, 993, 999, 1001, 1010, 1011, 1012, 1015, 1024, 1042, 1045, 1080, 1090, 1095, 1097, 1098, 1099, 1109, 1167, 1170, 1214, 1234, 1243, 1245, 1349, 1352, 1433, 1492, 1494, 1503, 1512, 1524, 1600, 1630, 1701, 1720, 1723, 1731, 1755, 1807, 1812, 1813, 1863, 1981, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2023, 2049, 2053, 2115, 2140, 2401, 2535, 2565, 2583, 2773, 2774, 2801, 2869, 3024, 3050, 3128, 3129, 3150, 3306, 3389, 3544, 3545, 3546, 3547, 3548, 3549, 3550, 3551, 3552, 3553, 3554, 3555, 3556, 3557, 3558, 3559, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567, 3568, 3569, 3570, 3571, 3572, 3573, 3574, 3575, 3576, 3577, 3578, 3579, 3700, 4080, 4081, 4092, 4267, 4443, 4567, 4590, 4661, 4662, 4663, 4664, 4665, 4666, 4899, 5000, 5000, 5001, 5060, 5168, 5190, 5321, 5333, 5400, 5401, 5402, 5550, 5554, 5555, 5556, 5557, 5569, 5631, 5632, 5742, 5800, 5801, 5890, 5891, 5892, 6267, 6400, 6665, 6666, 6667, 6668, 6669, 6670, 6711, 6771, 6776, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890, 6939, 6969, 6970, 7000, 7001, 7070, 7215, 7300, 7301, 7306, 7307, 7308, 7424, 7467, 7511, 7597, 7626, 7789, 8011, 8102, 8181, 9408, 9535, 9872, 9873, 9874, 9875, 9898, 9989, 10066, 10067, 10167, 10168, 10520, 10607, 11000, 11223, 11927, 12076, 12223, 12345, 12346, 12361, 12362, 12363, 12631, 13000, 13223, 14500, 14501, 14502, 14503, 15000, 15382, 16484, 16772, 16969, 17072, 17166, 17300, 17449, 17499, 17500, 17569, 17593, 17777, 19191, 19864, 20001, 20002, 20005, 20023, 20034, 20808, 21544, 22222, 23005, 23006, 23023, 23032, 23432, 23444, 23456, 23456, 23476, 23477, 25685, 25686, 25836, 25982, 26274, 27184, 29104, 29891, 30001, 30003, 30029, 30100, 30101, 30102, 30103, 30103, 30133, 30303, 30947, 31336, 31337, 31338, 31339, 31666, 31785, 31787, 31788, 31789, 31791, 31792, 32100, 32418, 33333, 33577, 33777, 33911, 34324, 34555, 35555, 36549, 37237, 40412, 40421, 40422, 40423, 40425, 40426, 41337, 41666, 46147, 47262, 49301, 50130, 50505, 50766, 51996, 53001, 54283, 54320, 54321, 55165, 57341, 58339, 60000, 60411, 61348, 61466, 61603, 63485, 65000, 65390, 65432, 65535]:
                self.q.put(i)
            self.tcp_total=self.q.qsize()
        my_threads = [threading.Thread(target=self.tcp_scan_port) for i in range(self.thread_num)]
        for t in my_threads:
            t.start()
        for t in my_threads:
            t.join()

    def tcp_scan_port(self):
        '''
        扫描tcp相应端口
        :return: bool
        '''

        while not self.q.empty():
            if stop==1:
                break
            port = self.q.get()
            # SYN扫描,sr1返回一个应答包
            packet = IP(dst=self.ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=2, verbose=0,iface=self.iface)
            if not response:
                pass
            elif response.haslayer(TCP):
                if response[TCP].flags == 'SA':
                    if "1" in self.connect:
                        # 半连接
                        nm = nmap.PortScanner()
                        res = nm.scan(hosts=self.ip, arguments='-sS -e ' + str(self.iface)+' -p '+str(port))
                        # logger.info('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                    else:
                        # 全连接
                        packet2 = IP(dst=self.ip) / TCP(dport=port, flags='A', ack=(response[TCP].seq + 1))
                        response2 = sr1(packet2, timeout=2, verbose=0,iface=self.iface)
                        if response2:
                            nm = nmap.PortScanner()
                            res = nm.scan(hosts=self.ip, arguments='-sT -e '+str(self.iface)+' -p ' + str(port))
                        else:
                            return False

                    tcp_ports = []
                    if dict(res)['scan'] and res:
                        ret = dict(res)['scan'][self.ip]
                        if 'tcp' in ret:
                            tcp_ports = ret['tcp']
                    for port in tcp_ports:
                        self.result.append({"ip": self.ip, "port": str(port), "protocol": "TCP",
                                            "service": str(tcp_ports[port]['name']),
                                            "state": str(tcp_ports[port]['state'])})
                elif response[TCP].flags == 'RA':
                    pass
            self.tcp_done.put(port)
            # self.tcp_done.put(self.done.qsize())
        return True

    def udp_scan(self, udp_start, udp_end):
        '''
        udp端口扫描
        :param udp_start:
        :param udp_end:
        :return: json
        '''
        self.udp_done=Queue()
        if udp_start and udp_end:
            nmap_proc = NmapProcess(targets=self.ip, options='-sU -e '+str(self.iface)+' -p ' + str(udp_start) + "-" + str(udp_end))
            self.udp_total = int(udp_end) - int(udp_start) + 1
        else:
            self.log('[*]正在扫描常见UDP端口')
            nmap_proc = NmapProcess(targets=self.ip, options='-sU --top-ports 100'+' -e '+str(self.iface))
            self.udp_total = 100
        nmap_proc.run_background()
        while nmap_proc.is_running() and stop == 0:
            current= float(nmap_proc.progress)*self.udp_total*0.01
            self.udp_done.put(current)
            time.sleep(3)  # 3秒更新一次百分比

        if stop == 1:
            logger.info("停止扫描")
            self.log(log="[*]停止扫描", Done=True, current=0, total=100)
            return {'status': 2, 'msg': "停止扫描"}

        ScanEngine = nmap.PortScanner()
        res = ScanEngine.analyse_nmap_xml_scan(nmap_proc.stdout)
        udp_ports = []
        if dict(res)['scan'] and res:
            ret = dict(res)['scan'][self.ip]
            if 'udp' in ret:
                udp_ports = ret['udp']
        for port in udp_ports:
            if str(udp_ports[port]['name']) and 'open' in str(udp_ports[port]["state"]):
                self.result.append(
                    {"ip": self.ip, "port": str(port), "protocol": "UDP", "service": str(udp_ports[port]['name']),
                     "state": str(udp_ports[port]["state"])})
        self.udp_done.put(self.udp_total)

# if __name__ == '__main__':
#     scan = Portscan()
#     scan.run(ip='172.16.100.51', protocol='tcp udp', tcp_start=None, tcp_end=None,udp_start=1,udp_end=100,connect="1")
#     print(scan.result)

