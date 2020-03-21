#! /usr/bin/env python

import sqlite3
import contextlib
import datetime
import time
import threading
import random
from scapy.all import IP, sr1, TCP

class tt_sql():
    def __init__(self):
        self.worker_sleep = 60
        self.sql_file = 'db/tt.db'
        self.log_table = 'tt_log'
        self.swap_table = 'tt_swap'
        self.dev_table = 'tt_devicelist'
        self.rep_table = 'tt_report'

    def sql_wrap(self, sql_q, params = None, commit = False, select = False):
        with contextlib.closing(sqlite3.connect(self.sql_file)) as conn:
            with conn:
                with contextlib.closing(conn.cursor()) as c:
                    if params:
                        c.execute(sql_q, params)
                    else:
                        c.execute(sql_q)
                    if commit:
                        conn.commit()
                    if select == 'one':
                        data = c.fetchone()
                        return Data
                    elif select == True:
                        data = c.fetchall()
                        return data

    def create_tables(self) :
        sql_q = "CREATE TABLE IF NOT EXISTS " + self.log_table + """(
                id INTEGER PRIMARY KEY,
                datetime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                ip_dst TEXT,
                tcp_src INTEGER,
                tcp_dst INTEGER,
                read TEXT,
                incident_id INTEGER
                );"""
        self.sql_wrap(sql_q, commit = True)
        sql_q = "CREATE TABLE IF NOT EXISTS " + self.swap_table + """(
                id INTEGER PRIMARY KEY,
                datetime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                incident_id INTEGER,
                n_packets INTEGER
                );"""
        self.sql_wrap(sql_q, commit = True)
        sql_q = "CREATE TABLE IF NOT EXISTS " + self.dev_table + """(
                id integer PRIMARY KEY,
                ether_src TEXT,
                ports TEXT,
                smb TEXT,
                incident_id INTEGER,
                num_seen INTEGER
                );"""
        self.sql_wrap(sql_q, commit = True)
        sql_q = "CREATE TABLE IF NOT EXISTS " + self.rep_table + """(
                id integer PRIMARY KEY,
                datetime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                n_packets INTEGER,
                incident_id
                );"""
        self.sql_wrap(sql_q, commit = True)

    def insert_row_header(self, header):
        # Check if ether src is related to current incident
        incident = header[8]
        ether = header[2]
        sql_q = "SELECT DISTINCT ether_src, incident_id FROM " + self.swap_table + " WHERE ether_src = '" + ether + "'"
        swap = self.sql_wrap(sql_q, select = True)
        # If ether src exists on swap
        if swap:
            for s in swap:
                if ether == s[0]:
                    incident = s[1]
                    act = 'update'
                else:
                    incident = self.get_incident()
                    #self.new_device_chk(ether, incident)
                    act = 'add'
        else:
            incident = self.get_incident()
            #self.new_device_chk(ether, incident)
            act = 'add'
        head = (header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7], incident)
        sql_q = "INSERT INTO " + self.log_table + "(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read, incident_id) VALUES(?,?,?,?,?,?,?,?,?)"
        self.sql_wrap(sql_q, params = head, commit = True)
        # Check device list
        self.new_device_chk(ether, incident)
        # Open up some rows
        self.set_unread_open(incident)
        # Add or update swap
        self.read_filter(ether, incident, action = act)
        # Start worker to analyze swap data
        if act == 'add':
            print(" ** Worker thread for ether %s (incident id: %s) sleeping for %s seconds." % (ether, incident, self.worker_sleep))
            t = threading.Timer(self.worker_sleep, self.worker, [ether, incident]) 
            t.start()
            print(self.get_table(self.dev_table))
            print(self.get_table(self.rep_table))

    def worker(self, ether, incident):
        sql_q = "SELECT id, n_packets, filter, incident_id, ip_src FROM " + self.swap_table + " WHERE ether_src = '" + ether + "' AND incident_id =" + str(incident)
        select = self.sql_wrap(sql_q, select = True)
        if(select):
            id = str(select[0][0])
            n_pack = str(select[0][1])
            filt = select[0][2]
            inc = select[0][3]
            ip = select[0][4]
            print("Deleting swap for %s (incident %s)." % (ether, incident))
            sql_q = "DELETE FROM " + self.swap_table + " WHERE id = " + id
            self.sql_wrap(sql_q, commit = True)
            print("Creating report for %s (incident %s), filter %s" % (ether, inc, filt))
            sql_q = "INSERT INTO " + self.rep_table + "(datetime, filter, ether_src, ip_src, n_packets, incident_id) VALUES(?,?,?,?,?,?)"
            param = (datetime.datetime.now(), filt, ether, ip, n_pack, inc)
            self.sql_wrap(sql_q, params = param, commit = True)

    def inspect(self, ether):
        sql_q = "SELECT DISTINCT ip_src FROM " + self.log_table + " WHERE ether_src = '" + ether + "'"
        host = self.sql_wrap(sql_q, select = True)[0][0]
        ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 1723, 3389]
        port = []
        for dst_port in ports:
            src_port = random.randint(1025, 65534)
            resp = sr1(
                    IP(dst = host)/TCP(sport = src_port, dport = dst_port, flags = "S"), timeout = 1, verbose = 0,)
            if resp:
                if resp.haslayer(TCP):
                    if resp.getlayer(TCP).flags == 0x12:
                        # Send a RST to close the connection
                        # RST vs FIN for filter
                        send_rst = sr1(
                                IP(dst = host)/TCP(sport = src_port, dport = dst_port, flags = 'R'), timeout = 1, verbose = 0,)
                        port.append(dst_port)
        if port:
            prt = ""
            for p in range(len(port)):
                a = str(port[p])
                if p == len(port) - 1:
                    prt = prt + a
                else:
                    prt = prt + a + ", "
                sql_q = "UPDATE " + self.dev_table + " SET ports = '" + prt + "' WHERE ether_src = '" + ether + "'"
                self.sql_wrap(sql_q, commit = True)

    def get_incident(self):
        sql_q = "SELECT MAX(incident_id) FROM " + self.log_table
        max_inc = self.sql_wrap(sql_q, select = True)[0][0]
        # Set incident to 1 if no incidents
        if max_inc == None:
            incident = 1
        else:
            incident = max_inc + 1
        return incident

    def set_unread_open(self, incident):
        # Read 'unread' rows and set to 'open'
        sql_q = "UPDATE " + self.log_table + " SET read = 'open' WHERE read = 'unread' AND incident_id = " + str(incident)
        self.sql_wrap(sql_q, commit = True)
        # Get open records with current incident id
        sql_q = "SELECT ether_src FROM " + self.log_table + " WHERE read = 'open' AND incident_id = " + str(incident)
        ether = self.sql_wrap(sql_q, select = True)
        #print(self.get_table(self.swap_table))

    # Add device to device table if it doesn't exist
    def new_device_chk(self, ether, incident):
        sql_q = "SELECT ether_src, incident_id FROM " + self.dev_table + " WHERE ether_src = '" + ether  + "'"
        dev = self.sql_wrap(sql_q, select = True)
        if not dev:
            print(" * Device %s has never been seen before.  Adding to device list." % ether)
            smb = 0
            n_seen = 1
            param = (ether, incident, n_seen)
            sql_q = "INSERT INTO " + self.dev_table + "(ether_src, incident_id, num_seen) VALUES(?,?,?)"
            self.sql_wrap(sql_q, params = param, commit = True)
            # Perform port scan and smb lookup
            t = threading.Thread(target = self.inspect, args = (ether,))
            t.start()
        else:
            sql_q = "SELECT id, incident_id, num_seen FROM " + self.dev_table + " WHERE ether_src = '" + ether + "'"
            dev = self.sql_wrap(sql_q, select = True)[0]
            id = dev[0]
            inc = dev[1]
            cnt = dev[2] + 1
            if incident != inc:
                print(" * Device %s has been seen before on incident %s.  Updating seen count to %s." % (ether, inc, cnt))
                # If ether seen on previous incident, increment num_seen
                sql_q = "UPDATE " + self.dev_table + " SET num_seen = " + str(cnt) + ", incident_id = " + str(incident) + " WHERE id = " + str(id)
                self.sql_wrap(sql_q, commit = True)

    # Get count of incidents for each packet filter
    def read_filter(self, ether, incident, action = None):
        filt = ['icmp-echo', 'tcp-syn', 'tcp-fin']
        for f in range(len(filt)):
            # Get data from log
            sql_q = "SELECT filter, ether_src, ip_src, incident_id, COUNT(ether_src) FROM " + self.log_table + " WHERE filter = '" + filt[f] + "'"
            sql_q += " AND read = 'open' AND incident_id = " + str(incident) + " AND ether_src = '" + ether + "'"
            select = self.sql_wrap(sql_q, select = True)[0]
            # If match for ether, filter, incident
            if select[0]:
                # Set open records for filter, ether, incident to read
                sql_q = "UPDATE " + self.log_table + " SET read = 'read' WHERE filter = '" + filt[f] + "' AND read = 'open' AND incident_id = " + str(incident) + " AND ether_src = '" + ether + "'"
                self.sql_wrap(sql_q, commit = True)
                if action == 'add':
                # If filter, ether, and incident exist in log
                    param = (datetime.datetime.now(), select[0], select[1], select[2], select[3], select[4])
                    sql_q = "INSERT INTO " + self.swap_table + "(datetime, filter, ether_src, ip_src, incident_id, n_packets) VALUES(?,?,?,?,?,?)"
                    self.sql_wrap(sql_q, params = param, commit = True)
                    # Set open records for filter, ether, incident to read
                elif action == 'update':
                    sql_q = "SELECT id, n_packets FROM " + self.swap_table + " WHERE ether_src = '" + ether + "' AND incident_id = " + str(incident) + " AND filter = '" + filt[f] + "'"
                    s = self.sql_wrap(sql_q, select = True)
                    if s:
                        id = str(s[0][0])
                        n_pack = str(s[0][1] + 1)
                        sql_q = "UPDATE " + self.swap_table + " SET n_packets = " + n_pack + " WHERE id = " + id
                        self.sql_wrap(sql_q, commit = True)

    def get_table(self, table):
        sql_q = "SELECT * FROM " + table
        data = self.sql_wrap(sql_q, select = True)
        return data
