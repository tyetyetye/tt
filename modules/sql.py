#! /usr/bin/env python

import sqlite3
import contextlib
import datetime
import time
import threading
#from threading import Timer,
import random
from scapy.all import IP, TCP, sr1
from modules.nbstat import smb_name

worker_sleep = 3
sql_file = 'db/tt.db'
log_table = 'tt_log'
swap_table = 'tt_swap'
dev_table = 'tt_devicelist'
rep_table = 'tt_report'
scan_ports = [135, 137, 445, 3389]
filters = ['icmp-echo', 'tcp-syn', 'tcp-fin']
white_mac = '88:51:fb:5a:ca:c0'

# Wrapper function for sql queries
def sql(sql_q, params = None, commit = False, select = False):
    with contextlib.closing(sqlite3.connect(sql_file)) as conn:
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

def create_tables():
    sql_q = "CREATE TABLE IF NOT EXISTS " + log_table + """(
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
    sql(sql_q, commit = True)
    sql_q = "CREATE TABLE IF NOT EXISTS " + swap_table + """(
            id INTEGER PRIMARY KEY,
            datetime TIMESTAMP,
            filter TEXT,
            ether_src TEXT,
            ip_src TEXT,
            incident_id INTEGER,
            n_packets INTEGER
            );"""
    sql(sql_q, commit = True)
    sql_q = "CREATE TABLE IF NOT EXISTS " + dev_table + """(
            id integer PRIMARY KEY,
            ether_src TEXT,
            ports TEXT,
            smb TEXT,
            incident_id INTEGER,
            num_seen INTEGER
            );"""
    sql(sql_q, commit = True)
    sql_q = "CREATE TABLE IF NOT EXISTS " + rep_table + """(
            id integer PRIMARY KEY,
            datetime TIMESTAMP,
            filter TEXT,
            ether_src TEXT,
            ip_src TEXT,
            n_packets INTEGER,
            incident_id
            );"""
    sql(sql_q, commit = True)

def insert_header(header):
    incident = header[8]
    ether = header[2]
    # Do nothing if it our MAC
    if not ether in white_mac:
        # Check if ether src is related to current incident
        sql_q = "SELECT DISTINCT ether_src, incident_id FROM " + swap_table + " WHERE ether_src = '" + ether + "'"
        swap = sql(sql_q, select = True)
        # If ether src exists on swap
        if swap:
            for s in swap:
                if ether == s[0]:
                    incident = s[1]
                    act = 'update'
                else:
                    incident = get_incident()
                    act = 'add'
        else:
            incident = get_incident()
            act = 'add'
        head = (header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7], incident)
        sql_q = "INSERT INTO " + log_table + "(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read, incident_id) VALUES(?,?,?,?,?,?,?,?,?)"
        sql(sql_q, params = head, commit = True)
        # Check device list
        new_device_chk(ether, incident)
        # Open up some rows
        set_unread_open(incident)
        # Add or update swap
        read_filter(ether, incident, action = act)
        # Start worker to analyze swap data
        if act == 'add':
            print(" ** Worker thread for ether %s (incident id: %s) sleeping for %s seconds." % (ether, incident, worker_sleep))
            t = threading.Timer(worker_sleep, worker, [ether, incident]) 
            t.start()

def worker(ether, incident):
    sql_q = "SELECT id, n_packets, filter, incident_id, ip_src FROM " + swap_table + " WHERE ether_src = '" + ether + "' AND incident_id =" + str(incident)
    select = sql(sql_q, select = True)
    if(select):
        id = str(select[0][0])
        n_pack = str(select[0][1])
        filt = select[0][2]
        inc = select[0][3]
        ip = select[0][4]
        sql_q = "DELETE FROM " + swap_table + " WHERE id = " + id
        sql(sql_q, commit = True)
        print("Creating report for %s (incident %s), filter %s" % (ether, inc, filt))
        sql_q = "INSERT INTO " + rep_table + "(datetime, filter, ether_src, ip_src, n_packets, incident_id) VALUES(?,?,?,?,?,?)"
        param = (datetime.datetime.now(), filt, ether, ip, n_pack, inc)
        sql(sql_q, params = param, commit = True)
        print(get_table(dev_table))
        #print(get_table(rep_table))

def tcp_scan(ether):
    port = []
    sql_q = "SELECT DISTINCT ip_src FROM " + log_table + " WHERE ether_src = '" + ether + "'"
    host = sql(sql_q, select = True)[0][0]
    for dst_port in scan_ports:
        src_port = random.randint(1025, 65534)
        resp = sr1(
                IP(dst = host)/TCP(sport = src_port, dport = dst_port, flags = 'S'), timeout = 1, verbose = 0,)
        if resp:
            if resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    # Send a RST to close the connection
                    send_rst = sr1(
                            IP(dst = host)/TCP(sport = src_port, dport = dst_port, flags = 'R',), timeout = 1, verbose = 0,)
                    port.append(dst_port)
                    # Todo if 135 is not open, edit nbstat to work for 145
                    if dst_port == 135:
                        smb_n = smb_name(host, dst_port)
                        if smb_n:
                            sql_q = "UPDATE " + dev_table + " SET smb = '" + smb_n + "' WHERE ether_src = '" + ether + "'"
                            sql(sql_q, commit = True)
    if port:
        prt = ""
        for p in range(len(port)):
            if p == len(port) - 1:
                prt = prt + str(port[p])
            else:
                prt = prt + str(port[p]) + ", "
            sql_q = "UPDATE " + dev_table + " SET ports = '" + prt + "' WHERE ether_src = '" + ether + "'"
            sql(sql_q, commit = True)

def get_incident():
    sql_q = "SELECT MAX(incident_id) FROM " + log_table
    max_inc = sql(sql_q, select = True)[0][0]
    # Set incident to 1 if no incidents
    if max_inc == None:
        incident = 1
    else:
        incident = max_inc + 1
    return incident

def set_unread_open(incident):
    # Read 'unread' rows and set to 'open'
    sql_q = "UPDATE " + log_table + " SET read = 'open' WHERE read = 'unread' AND incident_id = " + str(incident)
    sql(sql_q, commit = True)
    # Get open records with current incident id
    sql_q = "SELECT ether_src FROM " + log_table + " WHERE read = 'open' AND incident_id = " + str(incident)
    ether = sql(sql_q, select = True)
    #print(get_table(swap_table))

# Add device to device table if it doesn't exist
def new_device_chk(ether, incident):
    sql_q = "SELECT ether_src, incident_id FROM " + dev_table + " WHERE ether_src = '" + ether  + "'"
    dev = sql(sql_q, select = True)
    if not dev:
        print(" * Device %s has never been seen before.  Adding to device list." % ether)
        smb = 0
        n_seen = 1
        param = (ether, incident, n_seen)
        sql_q = "INSERT INTO " + dev_table + "(ether_src, incident_id, num_seen) VALUES(?,?,?)"
        sql(sql_q, params = param, commit = True)
        # Perform port scan and smb lookup
        t = threading.Thread(target = tcp_scan, args = (ether,))
        t.start()
    else:
        sql_q = "SELECT id, incident_id, num_seen FROM " + dev_table + " WHERE ether_src = '" + ether + "'"
        dev = sql(sql_q, select = True)[0]
        id = dev[0]
        inc = dev[1]
        cnt = dev[2] + 1
        if incident != inc:
            print(" * Device %s has been seen before on incident %s.  Updating seen count to %s." % (ether, inc, cnt))
            # If ether seen on previous incident, increment num_seen
            sql_q = "UPDATE " + dev_table + " SET num_seen = " + str(cnt) + ", incident_id = " + str(incident) + " WHERE id = " + str(id)
            sql(sql_q, commit = True)

# Get count of incidents for each packet filter
def read_filter(ether, incident, action = None):
    for f in range(len(filters)):
        # Get data from log
        sql_q = "SELECT filter, ether_src, ip_src, incident_id, COUNT(ether_src) FROM " + log_table + " WHERE filter = '" + filters[f] + "'"
        sql_q += " AND read = 'open' AND incident_id = " + str(incident) + " AND ether_src = '" + ether + "'"
        select = sql(sql_q, select = True)[0]
        # If match for ether, filter, incident
        if select[0]:
            # Set open records for filter, ether, incident to read
            sql_q = "UPDATE " + log_table + " SET read = 'read' WHERE filter = '" + filters[f] + "' AND read = 'open' AND incident_id = " + str(incident) + " AND ether_src = '" + ether + "'"
            sql(sql_q, commit = True)
            if action == 'add':
            # If filter, ether, and incident exist in log
                param = (datetime.datetime.now(), select[0], select[1], select[2], select[3], select[4])
                sql_q = "INSERT INTO " + swap_table + "(datetime, filter, ether_src, ip_src, incident_id, n_packets) VALUES(?,?,?,?,?,?)"
                sql(sql_q, params = param, commit = True)
                # Set open records for filter, ether, incident to read
            elif action == 'update':
                sql_q = "SELECT id, n_packets FROM " + swap_table + " WHERE ether_src = '" + ether + "' AND incident_id = " + str(incident) + " AND filter = '" + filters[f] + "'"
                s = sql(sql_q, select = True)
                if s:
                    id = str(s[0][0])
                    n_pack = str(s[0][1] + 1)
                    sql_q = "UPDATE " + swap_table + " SET n_packets = " + n_pack + " WHERE id = " + id
                    sql(sql_q, commit = True)
    #print(get_table(swap_table))

def get_table(table):
    sql_q = "SELECT * FROM " + table
    data = sql(sql_q, select = True)
    return data
