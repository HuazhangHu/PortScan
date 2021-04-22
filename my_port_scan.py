# 端口扫描检测
from router import db, logger
from app.task.task import Task
from app.test.items.port_scan.portscan_base import Portscan
from app.task.taskscan.log import front_log
from app.system.utils.ncConfig import NCConfig
# 端口扫描检测项对应的数据库表映射类
from app.report.report_problem import del_problem, add_problem

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

    def log(self, log, Done=False, current=None, total=None):
        front_log(self.task_id, my_port_scan.id, log, Done, current, total)

    @staticmethod
    def get_iface():
        '''
        获取网卡信息
        return name 网卡名称，为空表示无该网卡信息
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
                # 分析是否通过标准
                # standard_id = Task(task_id).get_standard_id()
                # if standard_id is None:
                #     return True
                # analysis_standard = True
                # if standard_id == 'S-01':
                #     analysis_standard = my_port_scan.analysis_S1(result)
                # else:
                #     pass
                # return analysis_standard
        return True
