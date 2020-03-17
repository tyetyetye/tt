#! /usr/bin/env python

from modules.smeller import tt_smeller

sql_file = 'db/tt.db'
l_iface = 'eth0'
#l_iface = 'enp0s25'

smeller = tt_smeller(sql_file, l_iface)
