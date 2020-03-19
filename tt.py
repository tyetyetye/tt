#! /usr/bin/env python

from modules.smeller import tt_smeller
from modules.sql import tt_sql

sql_file = 'db/tt.db'
l_iface = 'eth0'
#l_iface = 'enp0s25'

sql = tt_sql()
sql.create_tables()
smeller = tt_smeller(sql, l_iface)
