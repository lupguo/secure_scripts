#!/usr/bin/env python
# -*- coding:utf-8 -*-
import logging
import os
import re
import subprocess

# 读取日志文件
from collections import defaultdict

# 在secure文件中失败次数达到阈值则会直接判定为恶意IP
threshold = 30

# secure.xxx文件名前缀
secure_file_prefix = 'test/secure'
# secure文件存储位置
secure_log_path = '/var/log/'
# hosts.deny文件位置
deny_path = '/etc/hosts.deny'
# secure_for_sshd.py脚本日志记录位置
log_file = '/var/log/deny_ips.log'


# 测试
# secure_log_path = './test/'
# deny_path = './test/hosts.deny'
# log_file = './test/deny_ips.log'


# 创建一个日志处理器
def initLogger():
    handler = logging.FileHandler(log_file)

    # 配置日志格式
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)

    # 初始化 logging 模块
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    return logger


log = initLogger()

# 定义一个正则表达式，用于匹配日志文件中的IP地址
ip_pattern = r'.*Failed password for.* from (\d+\.\d+\.\d+\.\d+).*'


# 获取登录失败的IP列表
def get_failed_ips():
    failed_ips = []
    for filename in os.listdir(secure_log_path):
        if filename.startswith(secure_file_prefix):
            secure_file = os.path.join(secure_log_path, filename)
            with open(secure_file, 'r') as f:
                for line in f:
                    match_obj = re.match(ip_pattern, line)
                    if match_obj:
                        failed_ips.append(match_obj.group(1))
    return failed_ips


# 获取host.deny中已拒绝的IP地址
def get_ip_deny_list():
    ip_dict = {}
    with open(deny_path, 'r') as f:
        for line in f:
            if line.strip().startswith('ALL'):
                ips = line.strip().split()[1:]
                for ip in ips:
                    ip_dict[ip] = True
    return ip_dict


# 添加/IP至hosts.deny
def add_to_deny(bad_ip):
    log.info('{} added to hosts.deny due to too many failed login attempts.'.format(bad_ip))

    with open(deny_path, 'a') as f:
        f.write(f'ALL: {bad_ip}\n')


def main():
    failed_ip_count = defaultdict(int)
    failed_ips = get_failed_ips()
    for failed_ip in failed_ips:
        failed_ip_count[failed_ip] += 1

    # 针对dict中失败ip的统计数量大于阈值的，加入到deny文件中
    deny_ips = get_ip_deny_list()
    for failed_ip in failed_ip_count:
        if failed_ip_count[failed_ip] > threshold and failed_ip not in deny_ips:
            add_to_deny(failed_ip)

    # 重启sshd服务以让防护生效
    subprocess.call(["systemctl", "restart", "sshd.service"])


if __name__ == '__main__':
    main()
    print("secure for sshd scan failed ips done!")
