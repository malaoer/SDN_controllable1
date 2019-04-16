# -*- coding:utf-8 -*-
"""
    策略表示：
         []
"""
import socket
import struct
import pytricia
import pprint
import time
from file_tool import *
from p_trie import *
from operator import itemgetter

final_policys = []


"""
     将String类型的IP地址转换为整数类型
    :param strIP:   192.168.142.21
    :return:    3232271893
"""

def strIP_to_intIP(strIP):
    return struct.unpack('!I', socket.inet_aton(strIP))[0]

"""
判断ip1是否包含ip2
:param ip1: 
:param ip1Mask:
:param ip2:
:param ip2Mask:
:return: rue ip1包含ip2；False：ip1不包含ip2
"""
def ipSupSet(self,ip1,ip1Mask,ip2,ip2Mask):

    ipOne = self.strIP_to_intIP(ip1)
    ipSec = self.strIP_to_intIP(ip2)
    flag = False
    if (ip1Mask > ip2Mask):
        flag =False
    if (((ipOne >>(32-ip1Mask))^(ipSec>>(32-ip1Mask))) == 0):
        flag = True
    return flag

"""
将IP地址用二进制表示
:param strIP: 192.168.64.0
:return: 11000000 10101000 01000000 00000000
"""
def convert(self,strIP):
    ip_list = strIP.split('.')
    lst = []
    for i in ip_list:
        two = bin(int(i,10)).lstrip("0b")
        lst.append(two.zfill(8))
    return " ".join(lst)

def creating_dict():
    """
    将policy.csv文件转换为字典列表的格式，并按照优先级的顺序进行排序
    :return:
    """
    policys = read_policy_file1()
    policys = sorted(policys, key=itemgetter('priority'))
    return policys

def check_layer2_layer4(policy):
    # 0.0.0.0/0 表示
    if (policy['src_ip'], policy['dst_ip']) == ('0.0.0.0/0', '0.0.0.0/0'):
        if (policy['src_mac'], policy['dst_mac'], policy['src_start'], policy['dst_end']) != (
        '00:00:00:00:00:00', '00:00:00:00:00:00', '0', '0'):
            return True
        else:
            return False
    else:
        return False

def add_policy_to_patricia(policy,pyt_src,pyt_dst):
    """
    将策略的源和目的地址的IP地址添加到Patricia
    patricia ：Python的IP地址查找模块
    :param policy:
    :param pyt_src:
    :param pyt_dst:
    :return:
    """
    temp = []
    if pyt_src.has_key(policy['src_ip']):
        temp = pyt_src.get(policy['src_ip'])
        if int(policy['aasno']) not in temp:
            temp.append(int(policy['aasno']))
            pyt_src.insert(policy['src_ip'],temp)
    else:
        pyt_src.insert(policy['src_ip'],[int(policy['aasno'])])
    temp1 = []
    if pyt_dst.has_key(policy['dst_ip']):
        temp1 = pyt_dst.get(policy['dst_ip'])
        if int(policy['aasno']) not in temp1:
            temp1.append(int(policy['aasno']))
            pyt_dst.insert(policy['dst_ip'],temp1)
    else:
        pyt_dst.insert(policy['dst_ip'], [int(policy['aasno'])])
    return None

def find_all_parents(pyt, ip):
    """
    查找当前IP地址的父类
    :param pyt:
    :param ip:
    :return:
    """
    parent_all = []
    ip = pyt.parent(ip)
    while ip != None:
        parent_all.append(ip)
        ip = pyt.parent(ip)
    return parent_all

def check_policy_for_similars(policy, pyt_src, pyt_dst):
    src_conflict_policys = []
    dst_conflict_policys = []
    src_same_conflict_policys = []
    dst_same_conflict_policys = []
    if pyt_src.has_key(policy['src_ip']):

        src_same_conflict_policys = src_same_conflict_policys + pyt_src.get(policy['src_ip'])
    if pyt_dst.has_key(policy['dst_ip']):

        dst_same_conflict_policys = dst_same_conflict_policys + pyt_dst.get(policy['dst_ip'])
    src_child = pyt_src.children(policy["src_ip"])
    src_paren = find_all_parents(pyt_src, policy['src_ip'])
    dst_child = pyt_dst.children(policy['dst_ip'])
    dst_paren = find_all_parents(pyt_dst, policy['dst_ip'])
    src_child_conflict_policys = []
    dst_child_conflict_policys = []
    src_paren_conflict_policys = []
    dst_paren_conflict_policys = []
    if src_child != None :
        for i in src_child:
            src_child_conflict_rules = src_child_conflict_policys + pyt_src.get(i)
    if dst_child != None :
        for i in dst_child:
            dst_child_conflict_rules = dst_child_conflict_policys + pyt_dst.get(i)
    if src_paren != None :
        for i in src_paren:
            src_paren_conflict_rules = src_paren_conflict_policys + pyt_src.get(i)
    if dst_paren != None:
        for i in dst_paren:
            dst_paren_conflict_rules = dst_paren_conflict_policys + pyt_dst.get(i)

    src_all = src_child + src_paren
    dst_all = dst_child + dst_paren
    if src_all != None:
        for i in src_all:
            src_conflict_policys = src_conflict_policys + pyt_src.get(i)
    if dst_all != None:
        for i in dst_all:
            dst_conflict_policys = dst_conflict_policys + pyt_dst.get(i)
    src_conflict_policys = src_conflict_policys + src_same_conflict_policys
    dst_conflict_policys = dst_conflict_policys + dst_same_conflict_policys
    final_conflict_policys = list(set(src_conflict_policys) & set(dst_conflict_policys))

    return final_conflict_policys, src_same_conflict_rules, src_child_conflict_policys, src_paren_conflict_policys, dst_same_conflict_policys, dst_child_conflict_policys, dst_paren_conflict_policys


def subset_for_port(src_a_start,src_a_end,dst_a_start,dst_a_end,src_b_start,src_b_end,dst_b_start,dst_b_end):
    src_a = list(range(int(src_a_start),int(src_a_end)))
    dst_a = list(range(int(dst_a_start),int(dst_a_end)))
    src_b = list(range(int(src_b_start),int(src_b_end)))
    dst_b = list(range(int(dst_b_start),int(dst_b_end)))
    src_inter = list(set(src_a) & set(src_b))
    dst_inter = list(set(dst_a) & set(dst_b))
    if((int(src_a_start) == int(src_b_start)) and (int(src_a_end) == int(src_b_end)) and (int(dst_a_start) == int(dst_b_start)) and (int(dst_a_end) == int(dst_b_end))):
        port_conflict_type = 'exact'
    elif((int(src_a_start) >= int(src_b_start)) and (int(src_a_end) <= int(src_b_end)) and (int(dst_a_start) >= int(dst_b_start)) and (int(dst_a_end) <= int(dst_b_end))):
        port_conflict_type = 'equal'
    elif ((int(src_a_start) <= int(src_b_start) and int(src_a_end) >= int(src_b_end)) and (
            int(dst_a_start) <= int(dst_b_start) and int(dst_a_end) >= int(dst_b_end))):
        port_conflict_type = 'reverse'
    elif src_inter and dst_inter:
        port_conflict_type = 'intersect'
    else:
        port_conflict_type = 'completely'
    src_port_intersection_part = src_inter
    dst_port_intersection_part = dst_inter
    print()
    print("Length of Source port Intersection: ", len(src_port_intersection_part),
          "|| Length of Dest port Intersection: ", len(dst_port_intersection_part))
    return port_conflict_type, src_port_intersection_part, dst_port_intersection_part

def subset_for_ip(pyt_src,pyt_dst,con_policy,policy,src_same_conflict_rules,src_child_conflict_rules,src_parent_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_parent_conflict_rules):
    compare = int(con_policy['aasno'])
    conflict_type = ''
    final_type = ''
    src_intersection_part = ''
    dst_intersection_part = ''
    if (compare in src_same_conflict_rules) and (compare in dst_same_conflict_rules):
        """
        192.168.0.0/16,192.168.4.6/24,Allow
        192.168.0.0/16,192.168.4.6/24,Deny
        """
        conflict_type = 'exact'
        src_intersection_part = policy['src_ip']
        dst_intersection_part = policy['dst_ip']
    if ((compare in src_parent_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_parent_conflict_rules) or (compare in dst_same_conflict_rules)):
        conflict_type = 'equal'
        src_intersection_part = policy['src_ip']
        dst_intersection_part = policy['dst_ip']
    if ((compare in src_child_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_child_conflict_rules) or (compare in dst_same_conflict_rules)):
        conflict_type = 'reverse'
        src_intersection_part = con_policy['src_ip']
        dst_intersection_part = con_policy['dst_ip']
    if ((compare in src_child_conflict_rules) and (compare in dst_parent_conflict_rules)):
        conflict_type = 'intersect'
        src_intersection_part = con_policy['src_ip']
        dst_intersection_part = policy['dst_ip']
    if ((compare in src_parent_conflict_rules) and (compare in dst_child_conflict_rules)):
        conflict_type = 'intersect'
        src_intersection_part = policy['src_ip']
        dst_intersection_part = con_policy['dst_ip']
    port_conflict_type, src_port_intersection_part, dst_port_intersection_part = subset_for_port(
        policy['src_start'],policy['src_end'],policy['dst_start'],policy['dst_end'],con_policy['src_start'],con_policy['src_end'],con_policy['dst_start'],con_policy['dst_end'])

    print("Conflict_type in IP:" , conflict_type,"|| Conflict_type in Port：",port_conflict_type)

    if conflict_type == 'exact' and port_conflict_type == 'exact':
        final_type = 'exact'
    elif conflict_type == 'equal' and port_conflict_type == 'equal':
        final_type = 'equal'
    elif conflict_type == "reverse" and port_conflict_type == "reverse":
        final_type = 'reverse'
    elif conflict_type == "reverse" and port_conflict_type == "exact":
        final_type = "reverse"
    elif conflict_type == "exact" and port_conflict_type == "reverse":
        final_type = "reverse"
    elif conflict_type == "reverse" and port_conflict_type == "equal":
        final_type = "intersect"
    elif conflict_type == "equal" and port_conflict_type == "reverse":
        final_type = "intersect"
    elif conflict_type == "equal" and port_conflict_type == "exact":
        final_type = "equal"
    elif conflict_type == "exact" and port_conflict_type == "equal":
        final_type = "equal"
    elif conflict_type == "intersect" or port_conflict_type == "intersect":
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

def detection_algorithm(con_policy,policy,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules, src_paren_conflict_rules,
                        dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap):
    final_type, src_intersection_part, dst_intersection_part, src_port_intersection_part, dst_port_intersection_part = \
       subset_for_ip(pyt_src,pyt_dst,con_policy,policy,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)
    print("final_conflict_type:", final_type)
    print(policy['aasno'],"and ",con_policy['aasno'])
    if ((check_tcp_udp(policy)!=check_tcp_udp(con_policy)) or (final_type == 'different')):
        # print(policy['aasno'],"has no conflict with ", con_policy['aasno'])
        pass
    elif(final_type == 'exact'):
        if(policy['action'] == con_policy['action']):
            # print(policy['aasnno'],"has conflict with ",con_policy['aasno'])
            pass
        else:
            if (policy['priority'] == con_policy['priority']):
                print(policy['aasno'],"has intersection_different_action conflict with " ,con_policy['aasno'])
            else:
                print(policy['aasno'],"has Sheilding conflict with ",con_policy['aasno'])
    elif(final_type == 'equal'):
        if (policy['action'] == con_policy['action']):
            print(policy['aasnno'], "has Redundancy conflict with ", con_policy['aasno'])
        else:
            if (policy['priority'] == con_policy['priority']):
                print(policy['aasno'], "has intersection_different_action conflict with ", con_policy['aasno'])
            else:
                print(policy['aasno'], "has Sheilding conflict with ", con_policy['aasno'])
    elif(final_type == 'reverse'):
        if (policy['action'] == con_policy['action']):
            # 冗余冲突
            print(policy['aasnno'], "has Redundancy_removing conflict with ", con_policy['aasno'])
        else:
            if (policy['priority'] == con_policy['priority']):
                print(policy['aasno'], "has intersection_different_action conflict with ", con_policy['aasno'])
            else:
                print(policy['aasno'], "has Sheilding conflict with ", con_policy['aasno'])
    elif(final_type == 'intersect'):
        if (policy['action'] == con_policy['action']):
            # 冗余冲突
            print(policy['aasno'], "has Intersection_same_action conflict with ", con_policy['aasno'])
        else:
            if (policy['priority'] == con_policy['priority']):
                print(policy['aasno'], "has Intersection_different_action with same priority conflict with ", con_policy['aasno'])
            else:
                print(policy['aasno'], "has Intersection_different_action conflict with ", con_policy['aasno'])
    return rap


def detection1(policys, pyt_src, pyt_dst):
    print("Detection Policy Conflict：")
    i = 0
    rap = 100
    for policy in policys:
        i = int(policy['aasno'])-1
        for con_policy in policys:
            if policy == con_policy:
                continue
            print('aaa')
            print(conflict_rule_numbers[i])
            if int(con_policy['aasno']) in conflict_rule_numbers[i]:
                rap1 = detection_algorithm(con_policy,policy,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules, src_paren_conflict_rules,
                        dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap)
            else:
                # print(policy['aasno'],"has No conflict with ",con_policy['aasno'])
                pass

    print("Policy Conflict Detection finish!")



def policy_conflict_resolve(pyt_src,pyt_dst,policy,con_policy,conflict_type,rap,src_intersection_part=None,dst_intersection_part=None,src_port_intersection_part=None,
                            dst_part_intersection_part=None):
    pass




if __name__ == "__main__":
    policys = creating_dict()
    pyt_src,pyt_dst = patricia()
    i = 0
    for policy in policys:
        add_policy_to_patricia(policy,pyt_src,pyt_dst)

    conflict_rule_numbers = []
    src_same_conflict_rules = []
    src_child_conflict_rules = []
    src_paren_conflict_rules = []
    dst_same_conflict_rules = []
    dst_child_conflict_rules = []
    dst_paren_conflict_rules = []
    for policy in policys:
        check_policy_for_similars(policy,pyt_src,pyt_dst)
    for policy in policys:
        a, b, c, d, e, f, g = check_policy_for_similars(policy, pyt_src, pyt_dst)
        conflict_rule_numbers.append(a)
        src_same_conflict_rules.append(b)
        src_child_conflict_rules.append(c)
        src_paren_conflict_rules.append(d)
        dst_same_conflict_rules.append(e)
        dst_child_conflict_rules.append(f)
        dst_paren_conflict_rules.append(g)
        i = i + 1
    print(i)
    detection1(policys,pyt_src,pyt_dst)

