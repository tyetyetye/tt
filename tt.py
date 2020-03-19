#! /usr/bin/env python

from modules.smeller import tt_smeller
from modules.sql import tt_sql

#_iface = 'eth0'
l_iface = 'enp0s25'

sql = tt_sql()
sql.create_tables()
del sql
smeller = tt_smeller(l_iface)
