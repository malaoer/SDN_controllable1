import IPy
print(IPy.IP('204.229.128.0/24') in IPy.IP('204.229.128.0/20'))
print(IPy.IP('204.229.128.0/20') in IPy.IP('204.229.128.0/22'))

def conflict_resolve(policy,con_policy,pyt_src,pyt_dst,conflict_type,rap,src_intersection_part = None,dst_intersection_part =None,src_port_intersection_part=None,dst_port_intersection_part=None):
	if (conflict_type == "shadowing"):
		delete_policy_from_pt_ft(con_policy,pyt_src,pyt_dst)
		rap = 200

	elif (conflict_type == "redundancy_gamma_removing"):
		delete_policy_from_pt_ft(con_policy,pyt_src, pyt_dst)
		add_policy_to_patricia(policy,pyt_src, pyt_dst)
	elif (conflict_type == "redundancy"):
		#		print("No adding of R")
		pass

	elif (conflict_type == "generalization"):
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(x,pyt_src, pyt_dst)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(con_policy,pyt_src, pyt_dst)
	#		print("gamma Splitted")

	elif (conflict_type == "overlap"):
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(x,pyt_src, pyt_dst)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(con_policy,pyt_src, pyt_dst)
	#		print("gamma Splitted")

	elif (conflict_type == "correlation_prompt"):
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(x,pyt_src, pyt_dst)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(con_policy,pyt_src, pyt_dst)
	#		print("gamma Splitted:")

	elif (conflict_type == "correlation"):
		rap = 200
		src_ip_list = excluding_ip.func_exclude_ip(con_policy["src_ip"], src_intersection_part)
		dst_ip_list = excluding_ip.func_exclude_ip(con_policy["dst_ip"], dst_intersection_part)
		src_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["src_start"]), int(con_policy["src_end"]) + 1)), src_port_intersection_part)
		dst_port_list = excluding_port.func_exclude_port(
			list(range(int(con_policy["dst_start"]), int(con_policy["dst_end"]) + 1)), dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
															 policy, con_policy, pyt_src, pyt_dst)
		for x in f_list:
			add_policy_to_patricia(pyt_src, pyt_dst, x)
		#			add_rule_to_newft(x)
		delete_policy_from_pt_ft(con_policy,pyt_src, pyt_dst)
	#		print("gamma Splitted")

	return rap