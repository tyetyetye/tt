#! /usr/bin/env python

import datetime
import time
from scapy.all import AsyncSniffer, Ether, IP
from functools import partial
from modules.sql import tt_sql

l_iface = 'enp0s25'
#l_iface = 'eth0'

def main():
    sql = tt_sql()
    sql.create_tables()
    del sql

    # sniff for echos
    icmp_sniff = AsyncSniffer(iface=l_iface, prn=partial(logger, 'icmp-echo'), filter="icmp[icmptype] == icmp-echo", store=0)
    # sniff for tcp SYN
    tcp_syn_sniff = AsyncSniffer(iface=l_iface, prn=partial(logger, 'tcp-syn'), filter="tcp[tcpflags] & tcp-syn != 0", store=0)
    # sniff for tcp FIN
    tcp_fin_sniff = AsyncSniffer(iface=l_iface, prn=partial(logger, 'tcp-fin'), filter="tcp[tcpflags] & tcp-fin != 0", store=0)
    # start sniffing
    icmp_sniff.start()
    tcp_syn_sniff.start()
    tcp_fin_sniff.start()
    input()

def logger(pkt_filter, pkt):
    # Create dictionary to send to SQL
    if pkt_filter == 'tcp-syn' or pkt_filter == 'tcp-fin':
        tcp_sport = pkt[0][IP].sport
        tcp_dport = pkt[0][IP].dport
    else:
        tcp_sport = False
        tcp_dport = False
    header = (datetime.datetime.now(), # Now
        pkt_filter, # filter name
        pkt[0][Ether].src, # Ethernet source
        pkt[0][IP].src, # Source IP
        pkt[0][IP].dst, # Destination IP
        tcp_sport, # TCP source port
        tcp_dport,# TCP destination port
        'unread', # Read status
        0) # default incident ID
    # Do sql stuff
    sql = tt_sql()
    sql.insert_row_header(header)
    #if sql.set_unread_open():
        #print(sql.get_table('tt_log'))
        #time.sleep(30)
    #    pass

if __name__=='__main__':
    main()
