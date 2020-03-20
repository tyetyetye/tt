#! /usr/bin/env python

#from modules.investigate import tt_investigate
from modules.sql import tt_sql
from scapy.all import *
from functools import partial
import datetime
import time

class tt_smeller(tt_sql):
    def __init__(self, l_iface):
        # sniff for echos
        icmp_sniff = AsyncSniffer(iface=l_iface, prn=partial(self.logger, 'icmp-echo'), filter="icmp[icmptype] == icmp-echo", store=0)
        # sniff for tcp SYN
        tcp_syn_sniff = AsyncSniffer(iface=l_iface, prn=partial(self.logger, 'tcp-syn'), filter="tcp[tcpflags] & tcp-syn != 0", store=0)
        # sniff for tcp FIN
        tcp_fin_sniff = AsyncSniffer(iface=l_iface, prn=partial(self.logger, 'tcp-fin'), filter="tcp[tcpflags] & tcp-fin != 0", store=0)
        # start sniffing
        icmp_sniff.start()
        tcp_syn_sniff.start()
        tcp_fin_sniff.start()

        input()

    def logger(self, pkt_filter, pkt):
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
        #tt_investigate(sql)
        if sql.set_unread_open():
            time.sleep(30)
        else:
            pass
