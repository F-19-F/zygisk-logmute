# zygisk-logmute
A zygisk module that keeps logd from draining battery


## 1.How does it work?
By injecting nop opcode to __android_log_logd_logger


## 2.How to keep my app from muting?
```shell
packagename="com.myapp.example"
echo "${packagename}" >> /data/local/tmp/log_whitelist.conf
# let companion update whitelist
chmod 0660 /data/local/tmp/log_whitelist.conf
```