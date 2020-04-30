# -*- coding: utf-8 -*-
import re #正则表达式

def sort():
	'''排序 剔除P&R字符'''
	f1 = open(r'D:\Study Materials\Python\test\a.txt')
	r = [] # 变成Restrictive的需求
	p = [] # 变成Permissive的需求
	for line in f1:
		if 'P' in line:
			(addr1, per) = line.split('P', 1) # 以P为分隔符，分隔成两个
			r.append(addr1.strip() + '\n') # 提取前面的IP 保留到列表r中
		elif 'R' in line:
			(addr2, res) = line.split('R', 1) # 以R为分隔符，分隔成两个
			p.append(addr2.strip() + '\n') # 提取前面的IP 保留到列表p中
	f1.close()
	r.sort() # Restrictive IP列表排序
	p.sort() # Permissive IP列表排序
	return r,p # 返回多个参数 列表形式

def addnet():
	'''同一子网分组 添加前缀object-group network net_X.X.X.X'''
	f2 = open(r'D:\Study Materials\Python\test\r.txt', 'w')
	f3 = open(r'D:\Study Materials\Python\test\p.txt', 'w')
	one_step = sort() # 调用sort函数 sort函数里返回列表r,p列表
	r = one_step[0] # 调用第一个的Restrictive列表
	p = one_step[1] # 调用第二个的Permissive列表
	if len(p) > 0: # 判断是否存在需求
		l = ''.join(re.findall(r'\d+\.\d+\.\d+\.', p[0]))  # 数组转字符串 ''.join() /正则匹配C类子网
		p.insert(0, 'object-group network net_%s0\n' % l)  # 添加首个组名元素object-group network net_
		length_p = int(len(p))
		for i in range(length_p - 2):  # 列表有n个元素(第一个元素为以上添加的组名元素)对比n-1-1次
			j = ''.join(re.findall(r'\d+\.\d+\.\d+\.', p[i + 1]))  # 从第2个元素即第一个IP进行对比
			k = ''.join(re.findall(r'\d+\.\d+\.\d+\.', p[i + 2]))  # 第2个对比IP
			if j != k: # 两IP对比C类子网号是否相同
				'''两个子网号不匹配的的IP 第一个IP下一行加插字符串以实现添加下一个不同网段的组名'''
				p[i + 1] = p[i + 1] + ('\nobject-group network net_%s0\n' % k)
	if len(r) > 0: # 判断是否存在需求
		m = ''.join(re.findall(r'\d+\.\d+\.\d+\.', r[0]))
		r.insert(0, 'object-group network net_%s0\n' % m)
		length_r = int(len(r))
		for x in range(length_r - 2):  # 列表有n个对比n-2次
			y = ''.join(re.findall(r'\d+\.\d+\.\d+\.', r[x + 1]))  # 从第二个元素即第一个IP进行对比
			z = ''.join(re.findall(r'\d+\.\d+\.\d+\.', r[x + 2]))  # 第二个个IP
			if y != z:
				'''两个子网号不匹配的的IP 第一个IP下一行加插字符串以实现添加下一个不同网段的组名'''
				r[x + 1] = r[x + 1] + ('\nobject-group network net_%s0\n' % z)  # 不添加不改变下一个对比的元素

	f2.writelines(r) # 列表储存Restrictive的需求IP
	f3.writelines(p) # 列表储存Permissive的需求IP
	f2.close()
	f3.close()

def addprefix():
	'''添加前缀 ' '/no network-object host '''
	result = open(r'D:\Study Materials\Python\test\result.txt', 'w')
	result_r = []
	result_p = []
	f2 = open(r'D:\Study Materials\Python\test\r.txt')
	f3 = open(r'D:\Study Materials\Python\test\p.txt')

	for eachline_r in f2:
		if eachline_r[0] == '9':
			eachline_r = 'no network-object host ' + eachline_r
		result_r.append(eachline_r)

	for eachline_p in f3:
		if eachline_p[0] == '9':
			eachline_p = ' network-object host ' + eachline_p
		result_p.append(eachline_p)

	result.writelines(result_r)
	result.writelines('\n'*5)
	result.writelines(result_p)
	result.close()
	f2.close()
	f3.close()

def csdl():
	'''对比添加到csdl'''
	log = open(r'D:\AT&T\BSO changes\Log\e9r-pf-1a-2019.11.26.txt',encoding='utf-8') # 编码机制
	csdl_net = open(r'D:\Study Materials\Python\test\csdl_permit_IP.txt', 'w')
	result_add = open(r'D:\Study Materials\Python\test\result.txt', 'r+')  # 读取指针重头开始r +写入
	permit_ip = []  # 全部对比net
	permit_ip_result = []  # csdl_permit_IP 全部net字符
	extract = []  # 脚本需要对比的net
	csdl = []  # 需要添加的net
	pointer = 0
	'''提取特定行数内容'''
	for line in log:
		i = ''.join(re.findall(r'net_\d+\.\d+\.\d+\.0', line))
		if 'object-group network csdl_permit_IP' in line:
			pointer = 1  # 设定指针
		elif 'object-group network DNS_ATTACK_FROM_LAB' in line:
			break  # 跳出
		elif pointer == 1:
			permit_ip.append(i)
			permit_ip_result.append(line)
	'''提取每个网段'''
	for line in result_add:
		if 'object-group network ' in line:
			j = ''.join(re.findall(r'net_\d+\.\d+\.\d+\.0', line))
			extract.append(j)

	for k in extract:
		if k not in permit_ip: # 添加permit_ip组没有的网段
			csdl.append(' group-object %s\n' % k)
	if len(csdl) != 0: # 如存在需要添加的网段 则字符串前加入组名
		csdl.insert(0,'\nobject-group network csdl_permit_IP\n')
	csdl_net.writelines(permit_ip_result)
	result_add.writelines(csdl)
	log.close()
	csdl_net.close()
	result_add.close()


addnet()
addprefix()
csdl()






