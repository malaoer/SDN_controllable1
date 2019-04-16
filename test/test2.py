# coding=utf-8

import IPy
print(IPy.IP('233.73.153.58/32') in IPy.IP('233.73.0.0/16'))
print(IPy.IP('17.48.0.0/12') in IPy.IP('17.0.0.0/8'))