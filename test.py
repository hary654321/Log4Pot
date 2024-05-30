import re

# 输入的字符串
input_str = "172.16.130.69:8080"

# 使用正则表达式匹配 IP 地址部分
ip_address = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', input_str).group()

print(ip_address)