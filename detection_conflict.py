# -*- coding:utf-8 -*-
"""
当有一条或多条策略到达时，对策略进行冲突检测
"""
import IPy
import pytricia
import csv
from operator import itemgetter
from file_tool import *
import excluding_port
import excluding_ip
import add_all_policys_after_excluding

already_policys = []
se_number = 1001
def read_policy_file():
	# 读取polocy.csv文件，将csv文件转换为字典列表
	policys = []
	with open(".//data//already_policy.csv", newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			policys.append(row)
	return policys

def write_policy_file(policy):
	csv_columns =['aasno','priority','src_ip','dst_ip','src_start','src_end','dst_start','dst_end','nw_proto','action']
	try:
		with open(".//data//already_policy.csv",'a') as csvfile:
			writer = csv.DictWriter(csvfile,fieldnames=csv_columns)
			# writer.writeheader()
			writer.writerow(policy)
	except IOError as err:
		print("I/O error{0}:".format(err))
	return

def read_new_policy_file():
	# 读取polocy.csv文件，将csv文件转换为字典列表
	policys = []
	with open(".//data//new_policy.csv", newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			policys.append(row)
	return policys

def creating_dict():
	# 将policy.csv文件转换为字典列表的格式，并按照优先级的顺序进行排序
	policys = read_policy_file()
	policys = sorted(policys, key=itemgetter('priority'))
	return policys

def patricia():
	# 用于存储策略的源和目的ip,patricia :Python的IP地址查找模块
	pyt_src = pytricia.PyTricia()
	pyt_dst = pytricia.PyTricia()
	return pyt_src, pyt_dst

def add_policy_to_patricia(policy,pyt_src,pyt_dst):
	# 将策略的源和目的地址的IP地址添加到Patricia
	temp = []
	if pyt_src.has_key(policy['src_ip']):
		temp = pyt_src.get(policy['src_ip'])
		if int(policy['aasno']) not in temp:
			temp.append(int(policy['aasno']))
			pyt_src.insert(policy['src_ip'], temp)
	else:
		pyt_src.insert(policy['src_ip'], [int(policy['aasno'])])
	temp1 = []
	if pyt_dst.has_key(policy['dst_ip']):
		temp1 = pyt_dst.get(policy['dst_ip'])
		# print("temp1",temp1)
		if int(policy['aasno']) not in temp1:
			temp1.append(int(policy['aasno']))
			pyt_dst.insert(policy['dst_ip'], temp1)
	else:
		pyt_dst.insert(policy['dst_ip'], [int(policy['aasno'])])
	return None

def find_all_parents(pyt,ip):
	# 查找当前IP段的父类
	parent_all = []
	ip = pyt.parent(ip)
	while ip != None:
		parent_all.append(ip)
		ip = pyt.parent(ip)
	return parent_all

def check_policy_for_similars(policy, pyt_src, pyt_dst):
	# 判断是否存在与当前策略存在重叠域的情况
	src_conflict_policys = []
	dst_conflict_policys = []
	src_same_conflict_policys = []
	dst_same_conflict_policys = []
	# print('***************')
	# print(policy['src_ip'])
	if pyt_src.has_key(policy['src_ip']):
		# print('aaaa')
		src_same_conflict_policys = src_same_conflict_policys + pyt_src.get(policy['src_ip'])
	if pyt_dst.has_key(policy['dst_ip']):
		# print('bbbb')
		dst_same_conflict_policys = dst_same_conflict_policys + pyt_dst.get(policy['dst_ip'])
	# print("src_same_conflict_policys",src_same_conflict_policys)
	add_policy_to_patricia(policy, pyt_src, pyt_dst)
	src_child = pyt_src.children(policy["src_ip"])
	# print(policy['src_ip'],"src_child",src_child)
	src_parent = find_all_parents(pyt_src, policy['src_ip'])
	# print(policy['src_ip'],"src_parent",src_parent)
	dst_child = pyt_dst.children(policy['dst_ip'])
	# print(policy['dst_ip'],"dst_child",src_child)
	dst_parent = find_all_parents(pyt_dst, policy['dst_ip'])
	# print(policy['dst_ip'],"dst_parent",dst_parent)
	src_child_conflict_policys = []
	dst_child_conflict_policys = []
	src_parent_conflict_policys = []
	dst_parent_conflict_policys = []
	if src_child != None:
		for i in src_child:
			src_child_conflict_policys = src_child_conflict_policys + pyt_src.get(i)
	# print("src_child_conflict_policys", src_child_conflict_policys)
	if dst_child != None:
		for i in dst_child:
			dst_child_conflict_policys = dst_child_conflict_policys + pyt_dst.get(i)
	# print("dst_child_conflict_policys", dst_child_conflict_policys)
	if src_parent != None:
		for i in src_parent:
			src_parent_conflict_policys = src_parent_conflict_policys + pyt_src.get(i)
	# print("src_parent_conflict_policys", src_parent_conflict_policys)
	if dst_parent != None:
		for i in dst_parent:
			dst_parent_conflict_policys = dst_parent_conflict_policys + pyt_dst.get(i)
	# print("dst_parent_conflict_policys",dst_parent_conflict_policys)
	src_all = src_child + src_parent
	dst_all = dst_child + dst_parent
	# print("src_all",src_all)
	# print("dst_all",dst_all)
	if src_all != None:
		for i in src_all:
			# print("pyt_src.get(i)",pyt_src.get(i))
			src_conflict_policys = src_conflict_policys + pyt_src.get(i)

	if dst_all != None:
		for i in dst_all:
			# print("pyt_dst.get(i)",pyt_dst.get(i))
			dst_conflict_policys = dst_conflict_policys + pyt_dst.get(i)

	src_conflict_policys = src_conflict_policys + src_same_conflict_policys
	dst_conflict_policys = dst_conflict_policys + dst_same_conflict_policys

	possible_conflict_policys = list(set(src_conflict_policys) & set(dst_conflict_policys))
	return possible_conflict_policys,src_same_conflict_policys, src_child_conflict_policys, src_parent_conflict_policys,\
		   dst_same_conflict_policys, dst_child_conflict_policys, dst_parent_conflict_policys

def ip_sup_set(ip1,ip2):
	if IPy.IP(ip1) in IPy.IP(ip2):
		print(ip1," be included in",ip2)
	elif IPy.IP(ip2) in IPy.IP(ip1):
		print(ip1," include in ",ip2)
	else:
		print(ip1,ip2,"do not contain")

def subset_for_port(src_a_start,src_a_end,dst_a_start,dst_a_end,src_b_start,src_b_end,dst_b_start,dst_b_end):
	src_a = list(range(int(src_a_start),int(src_a_end)))
	dst_a = list(range(int(dst_a_start),int(dst_a_end)))
	src_b = list(range(int(src_b_start),int(src_b_end)))
	dst_b = list(range(int(dst_b_start),int(dst_b_end)))
	src_inter = list(set(src_a)& set(src_b))
	dst_inter = list(set(dst_a) & set(dst_b))

	if((int(src_a_start) == int(src_b_start)) and (int(src_a_end) == int(src_b_end)) and
			(int(dst_a_start) == int(dst_b_start)) and (int(dst_a_end) == int(dst_b_end))):
		port_conflict_type = 'exact'    # A = B

	elif((int(src_a_start) >= int(src_b_start)) and (int(src_a_end) <= int(src_b_end)) and
		 (int(dst_a_start) >= int(dst_b_start)) and (int(dst_a_end) <= int(dst_b_end))):
		port_conflict_type = 'equal'   # B ⊆ A
	elif ((int(src_a_start) <= int(src_b_start) and int(src_a_end) >= int(src_b_end)) and (
			int(dst_a_start) <= int(dst_b_start) and int(dst_a_end) >= int(dst_b_end))):
		port_conflict_type = 'reverse' # A ⊆  B
	elif src_inter and dst_inter:
		port_conflict_type = 'intersect'
	else:
		port_conflict_type = 'completely'
	src_port_intersection_part = src_inter
	dst_port_intersection_part = dst_inter
	# print("Length of Source port Intersection: ", len(src_port_intersection_part),
	# 	  "|| Length of Dest port Intersection: ", len(dst_port_intersection_part))
	return port_conflict_type, src_port_intersection_part, dst_port_intersection_part

def subset_for_ip(pyt_src,pyt_dst,con_policy,policy,src_same_conflict_policys,src_child_conflict_policys,
				  src_parent_conflict_policys,dst_same_conflict_policys,dst_child_conflict_policys,dst_parent_conflict_policys):
	# con_policy 已存在的策略
	# policy 欲添加的策略
	compare = int(con_policy['aasno'])
	src_intersection_part = ''
	dst_intersection_part = ''
	ip_conflict_type = ''
	final_type = ''

	if (compare in src_same_conflict_policys) and (compare in dst_same_conflict_policys):
		ip_conflict_type = 'exact'
		src_intersection_part = policy['src_ip']
		dst_intersection_part = policy['dst_ip']
	elif ((compare in src_parent_conflict_policys) or (compare in src_same_conflict_policys)) and ((compare in dst_parent_conflict_policys)
																								   or (compare in dst_same_conflict_policys)):
		ip_conflict_type = 'equal'
		src_intersection_part = policy['src_ip']
		dst_intersection_part = policy['dst_ip']
	elif ((compare in src_child_conflict_policys) or (compare in src_same_conflict_policys)) and ((compare in dst_child_conflict_policys)
																								  or (compare in dst_same_conflict_policys)):
		ip_conflict_type = 'reverse'
		src_intersection_part = con_policy['src_ip']
		dst_intersection_part = con_policy['dst_ip']
	elif(compare in src_child_conflict_policys) and (compare in dst_parent_conflict_policys):
		ip_conflict_type = 'intersect'
		src_intersection_part = con_policy['src_ip']
		dst_intersection_part = policy['dst_ip']
	elif(compare in src_parent_conflict_policys) and (compare in dst_child_conflict_policys):
		ip_conflict_type = 'intersect'
		src_intersection_part = policy['src_ip']
		dst_intersection_part = policy['dst_ip']

	port_conflict_type, src_port_intersection_part, dst_port_intersection_part = subset_for_port(
		policy['src_start'], policy['src_end'], policy['dst_start'], policy['dst_end'], con_policy['src_start'],
		con_policy['src_end'], con_policy['dst_start'], con_policy['dst_end'])
	print("ip_conflict_type",ip_conflict_type)
	print("port_conflict_type",port_conflict_type)
	if ip_conflict_type == 'exact' and port_conflict_type == 'exact':
		final_type = 'exact'
	elif ip_conflict_type == 'equal' and port_conflict_type == 'equal':
		final_type = 'equal'
	elif ip_conflict_type == "reverse" and port_conflict_type == "reverse":
		final_type = 'reverse'
	elif ip_conflict_type == "reverse" and port_conflict_type == "exact":
		final_type = "reverse"
	elif ip_conflict_type == "exact" and port_conflict_type == "reverse":
		final_type = "reverse"
	elif ip_conflict_type == "reverse" and port_conflict_type == "equal":
		final_type = "intersect"
	elif ip_conflict_type == "equal" and port_conflict_type == "reverse":
		final_type = "intersect"
	elif ip_conflict_type == "equal" and port_conflict_type == "exact":
		final_type = "equal"
	elif ip_conflict_type == "exact" and port_conflict_type == "equal":
		final_type = "equal"
	elif ip_conflict_type == "intersect" or port_conflict_type == "intersect":
		final_type = "intersect"
	elif port_conflict_type == "completely":
		final_type = "different"
	else:
		final_type = "intersect"
	return final_type, src_intersection_part, dst_intersection_part, src_port_intersection_part, dst_port_intersection_part

def check_tcp_udp(policy):
	if (policy['nw_proto'] == '6'):
		return 'True'
	else:
		return 'False'

def detection_algorithm(con_policy,policy,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules,
						src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap):

	final_type, src_intersection_part, dst_intersection_part, src_port_intersection_part, dst_port_intersection_part = \
	   subset_for_ip(pyt_src,pyt_dst,con_policy,policy,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,
					 dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)
	flag = False
	print("final_conflict_type:", final_type)
	if ((check_tcp_udp(policy)!=check_tcp_udp(con_policy)) or (final_type == 'different')):
		# print(policy['aasno'],"has no conflict with ", con_policy['aasno'])
		pass
	elif(final_type == 'exact'):
		# A1 = A2,B1 = B2,C1 = C2,action1 = action2  冗余
		if( policy['action'] == con_policy['action']):
			print(policy['aasno'],"and ",con_policy['aasno'],"exact Conflict is Redundary")
			rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "redundancy", rap)
			flag =True
		else:
			# A1 = A2,B1 = B2,C1 = C2,action1 ！= action2 priority1 != priority2   冲突
			if policy['priority'] == con_policy['priority']:
				print(policy['aasno'],"and ",con_policy['aasno'],'exact Conflict is Intersection_different_action_prompt')
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
			else:
				# A1 = A2,B1 = B2,C1 = C2,action1 ！= action2   覆盖冲突
				print(policy['aasno'],"and ",con_policy['aasno'],'exact Conflict is Shielding:')
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "shadowing", rap)
				flag = True
	elif(final_type == 'equal'):
		# （A1 包含 A2, B1 包含 B2, C1包含C2, action1 = action2） 冗余
		if (policy['action'] == con_policy['action']):
			print(policy['aasno'],"and ",con_policy['aasno'],"equal Conflict is Redundary")
			rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "redundancy_policy_removing", rap)
			flag = True
		else:
			if(policy['priority'] == con_policy['priority']):
				print(policy['aasno'],"and ",con_policy['aasno'],'equal Conflict is Intersection_different_action_prompt')
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
			else:
				print(policy['aasno'],"and ",con_policy['aasno'],"equal Conflict is Abstraction")
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "generalization",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
	elif(final_type == 'reverse'):
		# （A1 包含于 A2,B1 包含于 B2,C1 包含于 C2,action1 = action2）或 冗余
		if (policy['action'] == con_policy['action']):
			print(policy['aasno'],"and ",con_policy['aasno'],"reverse Conflict is Redundary")
			rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "redundancy_con_policy_removing", rap)
			flag = True
		else:
			if(policy['priority'] == con_policy['priority']):
				print(policy['aasno'],"and ",con_policy['aasno'],'reverse Conflict is Intersection_different_action_prompt')
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
			else:
				print(policy['aasno'],"and ",con_policy['aasno'],"reverse Conflict is Shielding")
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst,"shadowing",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
	elif(final_type == 'intersect'):

		if (policy['action'] == con_policy['action']):
			print(policy['aasno'],con_policy['aasno'],"intersect Conflict is Intersection_same_action")
			rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst,"overlap",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
			flag = True
		else:
			if(policy['priority'] == con_policy['priority']):
				print(policy['aasno'],"and ",con_policy['aasno'],'intersect Conflict is Intersection_different_action_prompt')
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
			else:
				print(policy['aasno'],"and ",con_policy['aasno'],"intersect Conflict is Intersection_different_action")
				rap = conflict_resolve(policy,con_policy,pyt_src, pyt_dst, "correlation",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
				flag = True
	return rap,flag

def conflict_resolve(policy,con_policy,pyt_src,pyt_dst,conflict_type,rap,src_intersection_part = None,dst_intersection_part =None,src_port_intersection_part=None,dst_port_intersection_part=None):

	if conflict_type == "redundancy" or conflict_type == "redundancy_policy_removing":  # 冗余冲突
		# （A1 包含 A2,B1 包含 B2,C1 包含 C2,action1 = action2） 冗余   处理   直接删除新的策略(不执行新下发的策略)
		pass
	elif conflict_type == "redundancy_con_policy_removing":    # 冗余冲突
		# （A1 包含于 A2,B1 包含于 B2,C1 包含于 C2,action1 = action2） 冗余    删除策略库中与新策略存在冲突的那条策略，将新策略加入策略库中，并提交给控制器执行
		delete_policy_from_pt_ft(con_policy,pyt_src,pyt_dst)
		add_policy_to_patricia(policy,pyt_src,pyt_dst)
		insert_policy_oracle(policy)
	elif conflict_type == "shadowing":      # 覆盖冲突   匹配域存在完全相同的情况
		if policy['priority']<=con_policy['priority']:
			pass
		else:
			delete_policy_from_pt_ft(con_policy,pyt_src,pyt_dst)
			add_policy_to_patricia(policy, pyt_src, pyt_dst)
			insert_policy_oracle(policy)
			rap = 200
	elif conflict_type == "generalization":    # 泛化冲突     匹配域中不存在完全相同的情况
		rap =200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_policys_after_excluding.add_all_policys(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(pyt_src, pyt_dst, x)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(pyt_src, pyt_dst, con_policy)


	elif conflict_type == "overlap":
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_policys_after_excluding.add_all_policys(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(pyt_src, pyt_dst, x)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(pyt_src, pyt_dst, con_policy)
	#		print("gamma Splitted")
	elif conflict_type == "correlation_prompt":
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_policys_after_excluding.add_all_policys(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(pyt_src, pyt_dst, x)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(pyt_src, pyt_dst, con_policy)
	#		print("gamma Splitted:")
	elif conflict_type == "correlation":
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_policys_after_excluding.add_all_policys(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(pyt_src, pyt_dst, x)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(pyt_src, pyt_dst, con_policy)
	#		print("gamma Splitted")

	return rap

def check_and_delete_in_final_policys(policy):
	for x in already_policys:
		if x['aasno'] == policy['aasno']:
			already_policys.remove(policy)
			break
		else:
			continue

def delete_policy_from_pt_ft(con_policy,pyt_src,pyt_dst):
	check_and_delete_in_final_policys(con_policy)  # Calling to check and delete final_device_values
	temp = []
	Ips = con_policy['src_ip']
	prio = int(con_policy['aasno'])
	temp = pyt_src.get(Ips)
	if temp is not None:
		if (prio not in temp):
			return None
		else:
			if len(temp) > 1:
				temp.remove(prio)
				pyt_src.insert(Ips, temp)
			else:
				pyt_src.delete(Ips)
	temp = []  # For Destination insertion
	Ipd = con_policy['dst_ip']
	temp = pyt_dst.get(Ipd)
	if temp is not None:
		if (prio not in temp):
			return None
		else:
			if len(temp) > 1:
				temp.remove(prio)
				pyt_dst.insert(Ipd, temp)
			else:
				pyt_dst.delete(Ipd)

def detection(already_policys,new_policys,pyt_src,pyt_dst):
	print("*************Detection Policy Conflict**************")
	i = 0
	rap =100
	for policy in new_policys:
		possible_conflict_policys,src_same_conflict_policys,src_child_conflict_policys, \
		src_parent_conflict_policys,dst_same_conflict_policys,dst_child_conflict_policys,dst_parent_conflict_policys = \
			check_policy_for_similars(policy, pyt_src, pyt_dst)
		rap1 = 0
		flag1 = False
		flag = []
		for a_policy in already_policys:
			if policy == a_policy:
				continue
			i = int(policy['aasno']) - 1

			if int(a_policy['aasno']) in possible_conflict_policys:
				rap1,flag1 = detection_algorithm(a_policy, policy, pyt_src, pyt_dst, src_same_conflict_policys,
									src_child_conflict_policys, src_parent_conflict_policys,
									dst_same_conflict_policys, dst_child_conflict_policys, dst_parent_conflict_policys, rap)
			else:
				flag1 = False
				print(policy['aasno'],"has No conflict with ",a_policy['aasno'])
			if flag1:
				flag.append('0')
			else:
				flag.append('1')
		# print(flag)
		if '0' in flag:
			print('Conflict')
		else:
			print(policy)
			add_policy_to_patricia(policy, pyt_src, pyt_dst)
			write_policy_file(policy)

	print("*************Policy Conflict Detection finish!***************")

if __name__=="__main__":

	# 读取以存在的策略
	policys = creating_dict()
	print('网络中现存的策略为：')
	for policy in policys:
		print(policy)

	# 构建相应的patricai树
	pyt_src, pyt_dst = patricia()
	for policy in policys:
		add_policy_to_patricia(policy, pyt_src, pyt_dst)
	# 读取新添加的策略
	new_policys = read_new_policy_file()
	# write_policy_file(new_policys)
	# for policy in new_policys:
	# 	add_policy_to_patricia(policy, pyt_src, pyt_dst)
	# 判断当前策略是否与现存策略存在冲突
	detection(policys,new_policys,pyt_src,pyt_dst)















