#!/usr/bin/env python

import subprocess

# 文件路径
secure_file = "/var/log/secure*"
hosts_deny_file = "/etc/hosts.deny"

# 定义恶意登录阈值
threshold = 100

# 获取所有登陆失败的IP地址并统计其出现次数
failed_logins = subprocess.check_output(f"grep 'Failed password' {secure_file} | awk '{{print $NF}}' | sort | uniq -c",
                                        shell=True)

# 把所有登陆失败的IP地址加入hosts.deny文件
for line in failed_logins.splitlines():
    count, ip = line.split()
    if int(count) >= threshold:
        with open(hosts_deny_file, "a") as f:
            f.write(f"ALL: {ip}\n")

# 重启sshd服务以让防护生效
subprocess.call(["systemctl", "restart", "sshd.service"])
