#! /usr/bin/env python

import sqlite3

class tt_sql():
    def __init__(self):
        self.sql_file = 'db/tt.db'

    def create_tables(self) :
        conn = sqlite3.connect(self.sql_file)
        c = conn.cursor()
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
        c.execute(sql_q)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_swap (
                id INTEGER PRIMARY KEY,
                dateteime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                n_packets INTEGER,
                incident_id INTEGER
                );"""
        c.execute(sql_q)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_devicelist (
                id integer PRIMARY KEY,
                ether_addr TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                smb_name TEXT,
                open_ports TEXT,
                num_seen INTEGER
                );"""
        c.execute(sql_q)
        conn.commit()
        conn.close()

    def open_rows(self):
        conn = sqlite3.connect(self.sql_file)
        c = conn.cursor()
        sql_q = "UPDATE tt_log SET read = 'open' WHERE read = 'unread'"
        c.execute(sql_q)
        conn.commit()
        sql_q = "SELECT * FROM tt_log WHERE read = 'open';"
        c.execute(sql_q)
        rows = c.fetchall()
        conn.close()
        return rows

    def insert_row_header(self, header):
        conn = sqlite3.connect(self.sql_file)
        c = conn.cursor()
        sql_q = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read) VALUES(?,?,?,?,?,?,?,?)"
        c.execute(sql_q, header)
        conn.commit()
        conn.close()

    def print_table(self, table):
        conn = sqlite3.connect(self.sql_file)
        c = conn.cursor()
        sql_q = "SELECT * FROM " + table
        c.execute(sql_q)
        res = c.fetchall()
        print(res)
        conn.close()
