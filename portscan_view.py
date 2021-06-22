from flask import request, jsonify
from app.test.routes.test_route import test
from app.test.items.port_scan.my_port_scan import my_port_scan
from router import logger

@test.route('/test/portscan/cherk',methods=['POST'])
def port_cherk():
    '''
    return status:0 ping不通  1 能ping通 2 错误
    '''
    try:
        params = request.get_json()
        ip = params['ip']#目标ip地址
        src=params['src']#源ip地址

    except Exception as e:
        logger.error("-端口扫描获取参数错误-%s" %e)
        return jsonify({'status': 2, 'msg': '参数不足'})

    try:
        test_ip = my_port_scan.test_ip(src,ip)#test_ip为portscan_base中的父类静态方法
        if test_ip:
            return jsonify({'status':1,'msg':'该IP能ping通'})
        else:
            return jsonify({'status':0,'msg':'该IP无法ping通'})

    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '端口扫描失败'})

@test.route('/test/port/start_scan', methods=['POST'])
def port_start_scan():
    try:
        params = request.get_json()
        task_id = params['taskId']
        protocol = params['protocol']
        ip = params['ip']#目标ip地址
        connect = params['connect']
        tcp_start = params['tcpStart']
        tcp_end = params['tcpEnd']
        udp_start = params['udpStart']
        udp_end = params['udpEnd']
        iface=params['iface']#网卡
        src=params['src']#源ip地址

        MAC=params['MAC']#目标MAC地址 字符串或为空
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '参数不足'})
    try:
        portscan = my_port_scan(task_id)
        result = portscan.run(ip=ip, src=src, iface=iface,MAC=MAC, protocol=protocol, tcp_start=tcp_start, tcp_end=tcp_end, udp_start=udp_start, udp_end=udp_end,connect=str(connect))
        if result['status'] == 1:
            my_port_scan.store(task_id=task_id, result=result['data'])
            my_port_scan.analysis(task_id=task_id, result=result['data'])
        return jsonify(result)
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '端口扫描失败'})


@test.route('/test/portscan/set_result', methods=['POST'])
def port_save_result():
    try:
        params = request.get_json()
        task_id = params['taskId']
        data = params['data']
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '参数不足'})
    result = my_port_scan.store(task_id=task_id, result=data)
    return jsonify(result)


@test.route('/test/portscan/get_result', methods=['POST'])
def portscan_result():
    #查看任务详情接口
    try:
        params = request.get_json()
        task_id = params['taskId']
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '参数不足'})
    result = my_port_scan.result(task_id)
    return jsonify({'status': 1, 'data': result})


@test.route('/test/portscan/stop_scan', methods=['POST'])
def port_stop_scan():
    try:
        params = request.get_json()
        task_id = params['taskId']
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '参数不足'})
    result = my_port_scan.stop()#stop继承而来
    if result:
        return jsonify(result)
    else:
        return jsonify({'status': 2, 'msg': '停止失败'})

@test.route('/test/portscan/get_iface_info',methods=['POST'])
def get_iface_info():
    try:
        params = request.get_json()
        task_id = params['task_id']
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 2, 'msg': '参数不足'})
    iface_info=my_port_scan.get_iface()
    return jsonify(iface_info)