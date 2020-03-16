#! /usr/bin/env python

from scapy.all import *
from functools import partial
import sqlite3
from modules.sql import tt_sql

sql_file = 'db/tt.db'

def tt_logger(l_filter, pkt):
    # Create dictionary to send to SQL
    pkt_dict = {'sniff_filter': l_filter}
    pkt_dict['ether_src'] = pkt[0][Ether].src
    pkt_dict['ip_src'] = pkt[0][IP].src
    pkt_dict['ip_dst'] = pkt[0][IP].dst
    pkt_dict['tcp_sport'] = 'NULL'
    pkt_dict['tdp_dport'] = 'NULL'
    if('tcp' in l_filter):
        pkt_dict['tcp_sport'] = pkt[0][IP].sport
        pkt_dict['tcp_dport'] = pkt[0][IP].dport
    # Try to connect to SQL database
    # Stop trying if fail
    sql = tt_sql()
    sql.insert_rows(pkt_dict)



# sniff for echos
icmp_sniff = AsyncSniffer(iface='eth0', prn=partial(tt_logger, 'icmp'), filter="icmp[icmptype] == icmp-echo", store=0)

# sniff for tcp SYN
#tcp_syn_sniff = AsyncSniffer(iface='enp0s25', prn=tt_logger(filter='tcp-syn'), filter="tcp[tcpflags] & tcp-syn != 0", store=0)

# sniff for tcp FIN
#tcp_fin_sniff = AsyncSniffer(iface='enp0s25', prn=tt_logger(filter='tcp-fin'), filter="tcp[tcpflags] & tcp-fin != 0", store=0)

icmp_sniff.start()
#tcp_syn_sniff.start()
#tcp_fin_sniff.start()

input()

icmp_sniff.stop()
#tcp_syn_sniff.stop()
#tcp_fin_sniff.start()
