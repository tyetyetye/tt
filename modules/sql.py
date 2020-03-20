#! /usr/bin/env python

import sqlite3
import contextlib
#import pandas as pd
#from sqlalchemy import create_engine
#from pandas.io import sql

class tt_sql():
    def __init__(self):
        self.sql_file = 'db/tt.db'

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
        sql_q = """CREATE TABLE IF NOT EXISTS tt_log (
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
        sql_q = """CREATE TABLE IF NOT EXISTS tt_swap (
                id INTEGER PRIMARY KEY,
                dateteime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                n_packets INTEGER,
                incident_id INTEGER
                );"""
        self.sql_wrap(sql_q, commit = True)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_devicelist (
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
        sql_q = "UPDATE tt_log SET read = 'open' WHERE read = 'unread'"
        self.sql_wrap(sql_q, commit = True)
        sql_q = "SELECT MAX(incident_id) FROM 'tt_log';"
        max_inc = self.sql_wrap(sql_q, select = True)[0][0]
        if(max_inc == (0,)):
            sql_q = "UPDATE tt_log SET incident_id = 1 WHERE read = 'open'"
            self.sql_wrap(sql_q, commit = True)
        else:
            sql_q = "UPDATE tt_log SET incident_id = " + str(max_inc + 1) + " WHERE read = 'open'"
            self.sql_wrap(sql_q, commit = True)
        sql_q = "SELECT ether_src FROM 'tt_log' WHERE read = 'open'"
        data = self.sql_wrap(sql_q, select = True)
        if data:
            self.new_device_chk(data)

    def new_device_chk(self, data):
        table = 'tt_devicelist'
        sql_q = "SELECT ether_src FROM " + table
        for item in data:
            it = item[0]
            sql_qa = sql_q + " WHERE ether_src = '" + it + "'"
            if not (self.sql_wrap(sql_qa, select = True)):
                param = (it, None, None, 1)
                sql_qb = "INSERT INTO " + table + "(ether_src, smb_name, open_ports, num_seen) VALUES(?,?,?,?)"
                self.sql_wrap(sql_qb, params = param, commit = True)
        print(self.get_table(table))

    def get_table(self, table):
        sql_q = "SELECT * FROM " + table
        data = self.sql_wrap(sql_q, select = True)
        return data
