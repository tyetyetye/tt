#! /usr/bin/env python

from modules.investigate import tt_investigate
from scapy.all import *
from functools import partial
import datetime
import contextlib
import sqlite3

class tt_smeller():
    def __init__(self, sql_file, l_iface):
        self.sql_file = sql_file
        self.l_iface = l_iface
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
            'unread')

        # Do sql stuff
        with contextlib.closing(sqlite3.connect(self.sql_file)) as self.conn:
            with self.conn:
                with contextlib.closing(self.conn.cursor()) as self.c:
                    self.create_log()
                    self.insert_rows(header)

        tt_investigate(self.sql_file)

    # Create SQL log table if not exists
    def create_log(self):
        sql_q = """CREATE TABLE IF NOT EXISTS tt_log (
                id INTEGER PRIMARY KEY,
                datetime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                ip_dst TEXT,
                tcp_src INTEGER,
                tcp_dst INTEGER,
                read TEXT
                );"""
        self.c.execute(sql_q)
        #sql_q = """CREATE TABLE IF NOT EXISTS tt_offenders (
        #        id integer PRIMARY KEY,
        #        ether_addr TEXT NOT NULL,
        #        ip_addr TEXT NOT NULL,
        #        smb_name TEXT,
        #        open_ports TEXT,
        #        num_seen INTEGER
        #        );"""
        #self.c.execute(sql_q)
        #self.conn.commit()

    # Insert header data into log table
    def insert_rows(self, header):
        sql_q = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read) VALUES(?,?,?,?,?,?,?,?)"
        self.c.execute(sql_q, header)
        self.conn.commit()

    def print_table(self, table):
        sql_q = "SELECT * FROM " + table
        self.c.execute(sql_q)
        res = self.c.fetchall()
        print(res)
