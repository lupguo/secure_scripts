# SSDH 加固

> 针对常规的个人云主机，经常遇到下面的恶意尝试，可以通过该操作方式增强SSHD防护

```bash
Last login: Thu Apr 20 21:53:15 CST 2023 on pts/0
Last failed login: Fri Apr 28 13:58:57 CST 2023 from 103.135.208.210 on ssh:notty
There were 17889 failed login attempts since the last successful login.
```

## 维护账号

1. 创建新的个人账号（密码不要太过简单），作为日常的ssh登录账号

## sshd_config配置加固

```
# sshd自定义端口
Port 自定义port

# 升级ed25519
HostKey /etc/ssh/ssh_host_ed25519_key

# 禁用ROOT登录
PermitRootLogin no

# 最大认证重试次数限定
MaxAuthTries 1
MaxSessions 10
```

## 新增crontab脚本，从secure文件统计恶意sshd的登录IP，加入`hosts.deny`进行拒绝

```bash
0 0 */14 * * /data/python/bin/secure_for_sshd.py >> /var/log/deny_ips.log
```

