import re
f = open(r'D:\AT&T\BSO changes\Log\e9r-pf-1a-2019.11.26.txt',encoding='utf-8')
f1 = open(r'D:\Study Materials\Python\test\BSO\csdl_permit_IP.txt', 'w')
f2 = open(r'D:\Study Materials\Python\test\BSO\result.txt','r+') #读取指针重头开始r +写入
permit_ip = [] # 全部对比net
permit_ip_result = [] #csdl_permit_IP 全部net字符
extract = [] # 脚本需要对比的net
csdl = ['object-group network csdl_permit_IP\n',] #需要添加的net
pointer = 0
'''提取特定行数内容'''
for line in f:
    i = ''.join(re.findall(r'net_\d+\.\d+\.\d+\.0', line))
    if 'object-group network csdl_permit_IP' in line:
        pointer = 1 #设定指针
    elif 'object-group network DNS_ATTACK_FROM_LAB' in line:
        break #跳出
    elif pointer == 1:
        permit_ip.append(i)
        permit_ip_result.append(line)
'''提取每个网段'''
for line in f2:
    if 'object-group network ' in line:
        j =''.join(re.findall(r'net_\d+\.\d+\.\d+\.0', line))
        extract.append(j)

for k in extract:
    if k not in permit_ip:
        csdl.append(' group-object %s\n' %k)
print(csdl)
f1.writelines(permit_ip_result)
f2.writelines(csdl)
f.close()
f1.close()
f2.close()


