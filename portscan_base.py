#coding:utf-8
'''
itb 端口与服务扫描
0630 改成二层发包
'''

from random import randint
import threading
from queue import Queue

import nmap
import time
from scapy.layers.inet import TCP, IP, UDP,Ether
from scapy.all import sr1,srp1
from libnmap.process import NmapProcess
from router import logger
from app.system.utils.ncConfig import NCConfig
import netifaces
# import logging
#
# logger = logging.getLogger(__name__)
stop=0

class Portscan():

    def __init__(self):
        global stop
        stop = 0
        self.result = Queue()
        self.ultimate = Queue()
        self.ip=''
        self.MAC=''
        self.src=''
        self.connect='1'
        self.thread_num=128#线程数
        self.q = Queue()
        self.tcp_total=0
        self.udp_total=0#总端口数
        self.udp_done=Queue()
        self.tcp_done=Queue()
        self.iface=''
        self.sleep=3 #log打印时间间隔

    def run(self, ip, src, iface, MAC="", protocol="tcp", tcp_start=None, tcp_end=None, udp_start=1, udp_end=1000, connect="1"):
        '''
        Args:
            ip: string 扫描的ip地址
            src:string 源ip地址
            iface:string 网卡名称
            MAC:string MAC地址
            protocol: string  'tcp' ,'udp'
            tcp_start: integer
            tcp_end: integer
            udp_start: integer
            udp_end: interger
            connect: char '1' or '0'
        Returns:
            json格式 {'status':'0' 停止 '1' 成功 '2' 失败
                          'data': list[dict{'ip','port','protocol','server','state'} , 'msg'}
        '''
        self.ip = ip
        self.src=src
        self.MAC=MAC
        self.result=Queue()
        self.ultimate=Queue()#存放最终的结果
        self.tcp_done = Queue()
        self.udp_done = Queue()
        self.connect=connect
        start_time=time.time()
        self.iface=iface
        self.src_mac=netifaces.ifaddresses(iface)[17][0]['addr']#获取该网卡的MAC地址
        print(' -------- source mac address :'+str(self.src_mac)+' -------- ')
        self.log(log="[*]开始端口扫描...")
        self.log(log="[*]目标IP地址：%s" %self.ip)
        if self.MAC:
            self.MAC=self.MAC.replace('-',':')#MAC地址格式转换
            self.log(log="[*]目标MAC地址为：%s"%self.MAC)
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
                if udp_start and udp_end:
                    self.udp_total = int(udp_end) - int(udp_start) + 1
                    thread_udp = threading.Thread(target=self.udp_scan, args=(udp_start, udp_end))
                else:
                    self.udp_total = 1000
                    thread_udp = threading.Thread(target=self.udp_scan, args=(1, 1000))
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
                logger.info(list(self.ultimate.queue))
                self.log(log="[*]停止扫描", Done=True, current=0, total=100)
                return {'status': 1, 'data':list(self.ultimate.queue),'msg': "停止扫描"}
            end_time=time.time()
            self.log(log="[*]扫描已完成,共花费{0} s".format(end_time-start_time), Done=True, current=100, total=100)
            logger.info(list(self.ultimate.queue))
            return {'status': 1, 'data': list(self.ultimate.queue), 'msg': "端口扫描成功"}

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
        return {'status': 1, 'msg': '正在停止扫描'}

    def get_result(self):
        '''
        获取目前的结果
        '''
        current_result = []  # socket发送目前的结果
        while not self.result.empty():
            if stop == 1:
                break
            port_result=self.result.get()
            current_result.append(port_result)
            self.ultimate.put(port_result)
        return current_result

    def log(self, log, Done=False, current=None, total=None,msg=None):
        pass

    def log_print(self, flag):
        '''
        :param flag:integer 1:tcp 2:udp 3: tcp and udp 0:error
        :return:
        0622 update:修改停止扫描显示剩余结果

        '''

        if flag == 1:  # 只进行tcp扫描
            while stop==0:
                if self.tcp_done.qsize()!=self.tcp_total:
                    current_result=self.get_result()
                    self.log(log='[*]TCP端口扫描完成%d/%d' % (self.tcp_done.qsize(),self.tcp_total), current=self.tcp_done.qsize(),total=self.tcp_total,msg=current_result)
                    time.sleep(self.sleep)
                else:
                    current_result = self.get_result()
                    self.log(log='[*]TCP端口扫描完成%d/%d' % (self.tcp_done.qsize(), self.tcp_total),current=self.tcp_done.qsize(), total=self.tcp_total, msg=current_result)
                    break

        elif flag == 2:  # 只进行udp扫描
            old=0
            while stop==0:
                if not self.udp_done.empty():
                    current=self.udp_done.get()
                    if current>=old:
                        current_result = self.get_result()
                        self.log(log='[*]UDP端口扫描完成%d/%d' % (current,self.udp_total), current=current,total=self.udp_total,msg=current_result)
                        old=current
                        time.sleep(self.sleep)
                    if current == self.udp_total:
                        current_result = self.get_result()
                        self.log(log='[*]UDP端口扫描完成%d/%d' % (current, self.udp_total), current=current,total=self.udp_total, msg=current_result)
                        break

        elif flag == 3: #0623修复UD/TCP log bug
            old=0
            udp_current=0
            tcp_current=0
            while stop==0:
                if not self.udp_done.empty():#UDP未结束
                    tcp_current=self.tcp_done.qsize()
                    udp_current=self.udp_done.get()
                    current=tcp_current+udp_current
                    if current>=old:
                        current_result = self.get_result()
                        self.log(log='[*]端口扫描完成%d/%d' % (current,self.tcp_total + self.udp_total),current=current,total=self.tcp_total + self.udp_total,msg=current_result)
                        old=current
                        time.sleep(self.sleep)
                if udp_current==self.udp_total:#UDP已结束
                    if tcp_current!=self.tcp_total:#TCP未结束
                        tcp_current=self.tcp_done.qsize()
                        current=tcp_current+udp_current
                        current_result = self.get_result()
                        self.log(log='[*]端口扫描完成%d/%d' % (current, self.tcp_total + self.udp_total), current=current,total=self.tcp_total + self.udp_total, msg=current_result)
                        time.sleep(self.sleep)
                    else:#TCP已结束
                        break
        else:
            return


    def tcp_scan(self, tcp_start, tcp_end):
        '''多线程tcp端口扫描函数
        :param tcp_start:
        :param tcp_end:
        :return:
        '''
        if tcp_start and tcp_end:
            #扫描指定端口区间
            self.tcp_total = int(tcp_end) + 1 - int(tcp_start)
            for i in range(int(tcp_start),int(tcp_end)+1):
                if stop==0:
                    self.q.put(i)
                else:
                    break
        else:
            self.tcp_total = 65535
            #扫描常见1-65535端口
            for i in range(1,65536):
                if stop==0:
                    self.q.put(i)
                else:
                    break
        my_threads = [threading.Thread(target=self.tcp_scan_port) for i in range(self.thread_num)]
        for t in my_threads:
            t.start()
        for t in my_threads:
            t.join()

    def tcp_scan_port(self):
        '''
        扫描tcp相应端口 update 0622 修复全连接bug
        '''
        while not self.q.empty():
            if stop==1:
                break
            port = self.q.get()
            # SYN扫描,sr1返回一个应答包
            if self.MAC=='':
                packet =  Ether(src=self.src_mac)/IP(dst=self.ip,src=self.src) / TCP(dport=port, flags='S')
            else:
                #指定目标MAC地址
                packet = Ether(dst=self.MAC,src=self.src_mac) / IP(dst=self.ip,src=self.src) / TCP(dport=port, flags='S')
            response = srp1(packet, timeout=2, verbose=0,iface=self.iface)

            if not response:
                pass   
            elif response.haslayer(TCP):
                if response[TCP].flags == 'SA' and stop==0:
                    if "1" in self.connect:
                        # 半连接
                        nm = nmap.PortScanner()
                        res = nm.scan(hosts=self.ip, arguments='-sS --send-ip -e ' + str(self.iface)+' -p '+str(port))
                        # logger.info('[+]TCP SYN端口扫描 %s %d \033[1;32;40m Open \033[0m' % (self.ip, port))
                    else:
                        if self.MAC=='':
                            packet2= Ether(src=self.src_mac)/IP(dst=self.ip,src=self.src) / TCP(dport=port, flags='A', ack=(response[TCP].seq + 1))
                        else:
                            packet2 = Ether(dst=self.MAC,src=self.src_mac)/IP(dst=self.ip,src=self.src) / TCP(dport=port, flags='A', ack=(response[TCP].seq + 1))
                        response2 = srp1(packet2, timeout=2, verbose=0,iface=self.iface)
                        if response2 and stop==0:
                            nm = nmap.PortScanner()
                            res = nm.scan(hosts=self.ip, arguments='-sT --send-ip -e '+str(self.iface)+' -p ' + str(port))
                        else:
                            res=None

                    tcp_ports = []
                    if res:
                        if dict(res)['scan']:
                            ret = dict(res)['scan'][self.ip]
                            if 'tcp' in ret:
                                tcp_ports = ret['tcp']
                        for port in tcp_ports:
                            self.result.put({"ip": self.ip, "port": str(port), "protocol": "TCP","service": str(tcp_ports[port]['name']),"state": str(tcp_ports[port]['state'])})
                elif response[TCP].flags == 'RA':
                    pass
            self.tcp_done.put(port)

    def udp_scan(self, udp_start, udp_end):
        '''
        udp端口扫描
        :param udp_start:
        :param udp_end:
        :return: json
        '''
        nmap_proc = NmapProcess(targets=self.ip,options='-sU -e ' + str(self.iface) + ' -p ' + str(udp_start) + "-" + str(udp_end))
        nmap_proc.run_background()
        while nmap_proc.is_running() and stop == 0:
            current= float(nmap_proc.progress)*self.udp_total*0.01
            self.udp_done.put(current)
            time.sleep(3)  # 3秒更新一次百分比
        if stop==1:
            return
        ScanEngine = nmap.PortScanner()
        res = ScanEngine.analyse_nmap_xml_scan(nmap_proc.stdout)
        udp_ports = []
        if dict(res)['scan'] and res:
            ret = dict(res)['scan'][self.ip]
            if 'udp' in ret:
                udp_ports = ret['udp']
        for port in udp_ports:
            if str(udp_ports[port]['name']) and 'open' in str(udp_ports[port]["state"]):
                self.result.put(
                    {"ip": self.ip, "port": str(port), "protocol": "UDP", "service": str(udp_ports[port]['name']),
                     "state": str(udp_ports[port]["state"])})
        self.udp_done.put(self.udp_total)

# if __name__ == '__main__':
#     scan = Portscan()
#     scan.run(ip='172.16.100.51', protocol='tcp udp', tcp_start=None, tcp_end=None,udp_start=1,udp_end=100,connect="1")


