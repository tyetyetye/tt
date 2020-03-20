#! /usr/bin/env python

import sqlite3
import contextlib
import datetime
import time

class tt_sql():
    def __init__(self):
        self.inc_id = 1
        self.sql_file = 'db/tt.db'
        self.log_table = 'tt_log'
        self.swap_table = 'tt_swap'
        self.dev_table = 'tt_devicelist'

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
                    if select:
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
                smb_name TEXT,
                open_ports TEXT,
                num_seen INTEGER
                );"""
        self.sql_wrap(sql_q, commit = True)

    def insert_row_header(self, header):
        sql_q = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read, incident_id) VALUES(?,?,?,?,?,?,?,?,?)"
        self.sql_wrap(sql_q, params = header, commit = True)

    def set_unread_open(self):
        # Read 'unread' rows and set to 'open'
        sql_q = "UPDATE " + self.log_table + " SET read = 'open' WHERE read = 'unread'"
        self.sql_wrap(sql_q, commit = True)
        # Get maximum incident id
        sql_q = "SELECT MAX(incident_id) FROM " + self.log_table
        max_inc = self.sql_wrap(sql_q, select = True)[0][0]
        # if incidents found, increment incident id
        if max_inc != (0,):
            self.inc_id =+ 1
        sql_q = "UPDATE " + self.log_table + " SET incident_id = " + str(self.inc_id) + " WHERE read = 'open'"
        self.sql_wrap(sql_q, commit = True)

        sql_q = "SELECT ether_src FROM " + self.log_table + " WHERE read = 'open' AND incident_id = " + str(self.inc_id)
        data = self.sql_wrap(sql_q, select = True)
        if data:
            # Add ether_src to dev_table if it doesn't exist there
            self.new_device_chk(data)
            # Check if swap is empty before proceeding
            if self.get_table(self.swap_table):
                # if swap is not empty, check if all 'unread' rows match src_ether on rows existing on swap
                # if they are the same, then pass (or should new investigator be called supplying new incident id?)
                # if they are different process with new incident ID (call investigator recursively?)
                return False
            else:
                self.swap_filter_count(data)
                print(self.get_table(self.swap_table))
                time.sleep(30)
                # check if any 'unread' rows ether_src match current incident ID
                # if they do, update swap and perform analysis
                # send emails after analysis
                # sleep for 5 minutes

    def log_swap_process(self):
        pass

    def new_device_chk(self, data):
        sql_q = "SELECT ether_src FROM " + self.dev_table
        for item in data:
            it = item[0]
            sql_qa = sql_q + " WHERE ether_src = '" + it + "'"
            if not (self.sql_wrap(sql_qa, select = True)):
                param = (it, None, None, 1)
                sql_qb = "INSERT INTO " + self.dev_table + "(ether_src, smb_name, open_ports, num_seen) VALUES(?,?,?,?)"
                self.sql_wrap(sql_qb, params = param, commit = True)

    def swap_filter_count(self, data):
        filt = ['icmp-echo', 'tcp-syn', 'tcp-fin']
        for e_src in data:
            for f in range(len(filt)):
                sql_q = "SELECT filter, ether_src, ip_src, incident_id, COUNT(ether_src) FROM " + self.log_table + " WHERE filter = '" + filt[f] + "'"
                sql_q += " AND read = 'open' AND incident_id = '" + str(self.inc_id) + "' AND ether_src ='" + str(e_src[0]) + "'"
                select = self.sql_wrap(sql_q, select = True)
                if select[0][0]:
                    sql_q = "INSERT INTO " + self.swap_table + "(datetime, filter, ether_src, ip_src, incident_id, n_packets) VALUES(?,?,?,?,?,?)"
                    values = (datetime.datetime.now(), select[0][0], select[0][1], select[0][2], select[0][3], select[0][4])
                    self.sql_wrap(sql_q, params = values, commit = True)
        # do port scan/smb lookup on all rows of swap

    def get_table(self, table):
        sql_q = "SELECT * FROM " + table
        data = self.sql_wrap(sql_q, select = True)
        return data
