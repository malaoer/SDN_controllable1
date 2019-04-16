#!/usr/bin/python
import ipaddress
def func_exclude_ip(mydict_ip,intersection_ip): 
	mydict_ip = ipaddress.ip_network(mydict_ip)
	intersection_ip = ipaddress.ip_network(intersection_ip)
	final = list(mydict_ip.address_exclude(intersection_ip))
	last = []
	for f in final:
		h = str(f)
#		print(h,"\t")
		last.append(h)
	if len(last) == 0:
		pot =  str(intersection_ip)
		return [pot]
	else:
		return last 
