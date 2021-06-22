# 端口扫描检测
from router import db, logger
from app.task.task import Task
from app.test.items.port_scan.portscan_base import Portscan
from app.task.taskscan.log import front_log
from app.system.utils.ncConfig import NCConfig
# 端口扫描检测项对应的数据库表映射类
from app.report.report_problem import del_problem, add_problem

import os

class Item_oua_portscan(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(20))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    state = db.Column(db.String(20))
    service = db.Column(db.String(80))
    task_id = db.Column(db.String(40))

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class my_port_scan(Portscan):

    id = "PT-13"

    def __init__(self, task_id):
        super().__init__()
        self.task_id = task_id

    def log(self, log, Done=False, current=None, total=None,msg=None):
        front_log(self.task_id, my_port_scan.id, log, Done, current, total, msg)

    @staticmethod
    def test_ip(src,ip):
        '''
        测试ip是否能够ping通
        :param ip:目标ip src:源ip
        :return: Bool True能够ping通 False 不能ping通
        '''
        backinfo = os.system('ping -I {0} -c 1 -w 10 {1}' .format(src,ip))
        #backinfo 0 能够ping通,1不通
        if not backinfo:
            return True
        else:
            return False

    @staticmethod
    def get_iface():
        '''
        获取网卡信息
        return
        1 wifi 2热点 4以太网线 vlan_id vlan
        name 网卡名称，为空表示无该网卡信息
        src 网卡ip地址
        '''
        iface={'1': {'name':'','src':''},
               '2':{'name':'','src':''},
               '4':{'name':'','src':''}}
        NCConfig.check_disconnect()
        NCConfig.redistribute_nc()
        all_info = NCConfig.get_all_iface_info()
        hotpot_name = NCConfig.get_nc_name(id=2)  # id=2 热点网卡
        local_name = NCConfig.get_nc_name(id=4)  # id=4 本地网卡
        if local_name is not None:
            iface['4']['name'] = local_name
            if NCConfig.get_ip(id=4):
                iface['4']['src']=NCConfig.get_ip(id=4)
        if hotpot_name is not None:
            iface['2']['name']= hotpot_name
            if NCConfig.get_ip(id=2):
                iface['2']['src']=NCConfig.get_ip(id=2)
        if all_info[0]['IPAddr']:
            iface['1']['name'] = all_info[0]['NicName']
            iface['1']['src']=all_info[0]['IPAddr']
        # 获取已配置的vlanID，并加入网卡信息
        ret_vir = NCConfig.get_all_virtual_iface_info()
        for vir in ret_vir:
            if '.' not in vir['NicName']:
                continue
            else:
                split_ret = vir['NicName'].split('.')
                id=split_ret[1]
                vlan_name='vlan_'+id
                iface[vlan_name]={'name':vir['NicName'],'src':vir['IPAddr']}

        return iface

    @staticmethod
    def result(task_id):
        data = Item_oua_portscan.query.filter_by(task_id=task_id).all()
        comment = Task(task_id).get_one_item(my_port_scan.id)
        return {'comment': comment, 'data': [res.to_dict() for res in data]}

    @staticmethod
    def store(task_id, result):
        try:
            #数据库查询
            ports = Item_oua_portscan.query.filter_by(task_id=task_id).all()
            for port in ports:
                db.session.delete(port)  # 删除旧结果
            db.session.commit()
            for p in result:
                db.session.add(Item_oua_portscan(ip=p['ip'], port=p['port'], protocol=p['protocol'], service=p['service'], state=p['state'], task_id=task_id))
            db.session.commit()
        except Exception as e:
            logger.error('存储端口扫描结果失败...{}'.format(e))
            return {'status': 2, 'msg': '存储端口扫描结果失败'}
        return {'status': 1, 'msg': '存储成功'}

    @staticmethod
    def analysis(task_id, result):
        """生成安全问题及建议.
        根据扫描结果生成被测样品存在的问题，连同安全建议一起存入report_problem表.
        前提：已执行了store().

        :return bool: True-执行成功, False-执行失败
        """
        if not del_problem(task_id, my_port_scan.id):
            return False

        for p in result:
            advice = '关闭危险端口'
            if str(p['port']) in ['21', '22', '23']:
                add_problem(
                    task_id, my_port_scan.id, '危险端口{}({})'.format(p['port'], p['service']), severity='',
                    description='扫描协议：{},{}:{},{}'.format(p['protocol'], "端口状态", p['state'], '可进行密码爆破'), advice=advice, test_object='{}'.format(p['ip'])
                )
            else:
                add_problem(
                    task_id,  my_port_scan.id, '危险端口{}({})'.format(p['port'], p['service']), severity='',
                    description='扫描协议：{},{}:{}'.format(p['protocol'], "端口状态", p['state']), advice=advice, test_object='{}'.format(p['ip'])
                )

        return True

