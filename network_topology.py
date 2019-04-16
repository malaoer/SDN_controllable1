# -*- coding:utf-8 -*-
import requests
import json
import networkx as nx
from file_tool import *

class network(object):

    def __init__(self):
        con_ip,con_port = read_network_conf()
        self.Con_Ip = con_ip
        self.Con_port= con_port

    def get_tolopogy(self):
        """
            get the topology of the  network
            获取网络的拓扑
        :return:
        """
        uri = "/restconf/operational/network-topology:network-topology/"
        url = 'http://' + self.CON_IP + ':' + self.CON_PORT + uri
        response = requests.get(url, auth=('admin', 'admin'))
        format_response = json.loads(response.text)
        topology = format_response['network-topology']['topology'][0]
        return topology

    def get_all_switchs(self, topology):
        """
            get all switch nodes in the network
            获取网络中所有的交换机节点
        :param topology:
        :return:
        """
        switchs = []
        assert 'node' in topology
        for j in topology['node']:
            if 'opendaylight-topology-inventory:inventory-node-ref' in j:
                node_id = j['node-id']
                switchs.append(node_id)
        # print('switchs：',switchs)
        # print(len(switchs))
        return switchs

    def get_all_hosts(self, topology):
        """
            get all host nodes in the network
            获取网络中所有的主机节点
        :param topology:
        :return:
        """
        hosts = []
        assert 'node' in topology
        for j in topology['node']:
            if 'host-tracker-service:addresses' in j:
                node_id = j['node-id']
                hosts.append(node_id)
            else:{
                print("Host node is not include in the network")
            }
        return hosts

    def get_all_links(self, topology):
        """
        get all links info in the network
        获取网络中存在的链路信息
        :param topology:
        :return: 网络中存在的链路
        """
        links = []
        assert 'link' in topology
        for link_info in topology['link']:
            if 'link-id' in link_info:
                link_id = link_info['link-id']
                links.append(link_id)
        # print(links)
        return links

    def get_all_switch_ports(self, topology, switch):
        """
        get all the port info of a switch
        获取某个交换机所有的端口信息
        :param topology: 拓扑信息
        :param switch: 交换机名
        :return: 该交换机含有的端口号
        """
        switch_ports = []
        assert 'node' in topology
        for j in topology['node']:
            if 'opendaylight-topology-inventory:inventory-node-ref' in j:
                if j['node-id'] == switch:
                    port_infos = j['termination-point']
                    for port_info in port_infos:
                        switch_ports.append(port_info['tp-id'])
                    # print(j['termination-point'])
        # print(switch_ports)
        return switch_ports

    def get_networkx_graph(self):
        """
        将网络拓扑转化为图的形式表示
        :return:
        """
        graph = nx.graph()


        return graph

    def draw_networkx_graph(self):
        pass









