#! /usr/bin/env python

import sqlite3
import datetime

class tt_sql():
    def __init__(self):
        sql_file = 'db/tt.db'
        self.conn = sqlite3.connect(sql_file)
        self.create_tables()

    def create_tables(self):
        c = self.conn.cursor()
        sql = """CREATE TABLE IF NOT EXISTS tt_log (
                id INTEGER PRIMARY KEY,
                datetime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                ip_dst TEXT,
                tcp_src INTEGER,
                tcp_dst INTEGER,
                read BOOL
                );"""
        c.execute(sql)
        sql = """CREATE TABLE IF NOT EXISTS tt_offenders (
                id integer PRIMARY KEY,
                ether_addr TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                smb_name TEXT,
                open_ports TEXT,
                num_seen INTEGER
                );"""
        c.execute(sql)
        self.conn.commit()
        c.close()

    def insert_rows(self, header):
        c = self.conn.cursor()
        sql = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read) VALUES(?,?,?,?,?,?,?,?)"
        c.execute(sql, header)
        self.conn.commit()
        c.close()

    def print_table(self, table):
        c = self.conn.cursor()
        sql = "SELECT * FROM " + table
        c.execute(sql)
        res = c.fetchall()
        print(res)
        c.close()
