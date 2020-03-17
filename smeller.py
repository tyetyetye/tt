#! /usr/bin/env python

from scapy.all import *
from functools import partial
import sqlite3
from modules.tt_sql import tt_sql
import datetime

sql_file = 'db/tt.db'

def tt_logger(l_filter, pkt):
    # Create dictionary to send to SQL
    if('tcp' in l_filter):
        tcp_sport = pkt[0][IP].sport
        tcp_dport = pkt[0][IP].dport
    else:
        tcp_sport = ''
        tdp_dport = ''
    header = [(
        datetime.datetime.now(), # Now
        l_filter, # filter name
        pkt[0][Ether].src, # Ethernet source
        pkt[0][IP].src, # Source IP
        pkt[0][IP].dst, # Destination IP
        'NULL', # TCP source port
        'NULL'# TCP destination port
        )]

    # Try to connect to SQL database
    sql = tt_sql()
    sql.insert_rows(header)
    sql.print_table('tt_log')



# sniff for echos
icmp_sniff = AsyncSniffer(iface='enp0s25', prn=partial(tt_logger, 'icmp'), filter="icmp[icmptype] == icmp-echo", store=0)

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
