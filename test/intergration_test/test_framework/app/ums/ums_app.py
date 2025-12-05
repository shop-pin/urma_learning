# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: ums app
"""
import logging
import os
import random

from common.constants import const

logging.basicConfig(levev=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))

SEPERATE_CONN = 0
UNI_CONN = 1

def prepare_test_case(host_list, case_path):
    common_path = f'{local_path}/../common'

    _cmd = f'cd {local_path};' \
           f'gcc ums_atom.cpp {case_path}/test_case.cpp ../common/test_log.c ../common/common.c  ../common/test_thread_pool.c {case_path}/../public.cpp -g '\
           f'-rdynamic -lstdc++  -w -O0 -fPIC  -fpermissive -o {case_path}/test_case'

    p_list = []
    for host in host_list:
        p_list.append(host.exec_cmd(_cmd, background=True))
    
    for p in p_list:
        p.wait()
        if p.ret != 0:
            log.error("gcc test_case failed!")
            raise

def check_port_nouse(host_list, port):
    cmd = f'cat /tmp/netstat.txt | grep {port} | wc -l'
    buf1 = host_list[0].exec_cmd(cmd).stdout
    buf2 = host_list[1].exec_cmd(cmd).stdout
    return int(buf1[0]) + int(buf2[0])

def gen_random_port(host_list, port_num=2):
    cmd = f'netstat -an > /tmp/netstat.txt'
    for host in host_list:
        host.exec_cmd(cmd)
    for i in range(100):
        tcp_port = random.randint(30000, 40000)
        log.info(f'---------- [ tcp_port = {i} {tcp_port} ] ----------')
        res = 0
        for j in range(port_num):
            up = tcp_port + j
            ret = check_port_nouse(host_list, up)
            res += ret
        if res == 0:
            break
    for i in range(100):
        udp_port = random.randint(40000, 50000)
        log.info(f'---------- [ udp_port = {i} {tcp_port} ] ----------')
        ret = check_port_nouse(host_list, up)
        if ret == 0:
            break
    return tcp_port, udp_port

def exec_test_case(host_list, path, server_num=1, client_num=1, random_host=True, **kwargs):
    log.info(f'---------- [Test path = {path} ] ----------')
    tcp_port, _test_port = gen_random_port(host_list)
    check = kwargs.get("check", True)
    app_num = server_num + client_num
    case_path = kwargs.get("case_path", "''")
    timeout = kwargs.get("timeout", 1800)
    test_port = kwargs.get("test_port", _test_port)
    ip_addrs = kwargs.get("ip_addrs", None)

    p_list = []
    test_host = []

    test_host.append(host_list[0])
    test_host.append(host_list[1])
        
    _test_ip = f'-i {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}' \
               f' -I {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}'
    
    log.info(f'--------start app{1} server--------')
    _cmd = f'{path}/test_case -a {app_num}:{1}:{tcp_port} -p {test_port} {_test_ip}' \
           f'  -x {case_path}'
    p_list.append(test_host[0].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

    log.info(f'--------start app{2} client--------')
    _cmd = f'{path}/test_case -a {app_num}:{2}:{tcp_port} -p {test_port} {_test_ip}' \
           f'-x {case_path}'
    p_list.append(test_host[1].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

    if check is True:
        for i in range(app_num):
            log.info(f'---------- [Test p{i + 1}.wait() ] ----------')
            p_list[i].wait()
        for i in range(app_num):
            log.info(f'---------- [Test assert p{i + 1} ] ----------')
            if p_list[i].ret != 0:
                log.error(f"exec_test_case failed!  p_list[{i}],ret={p_list[i].ret}!")
                raise
        p_list = []
    return p_list