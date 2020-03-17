#! /usr/bin/env python

import sqlite3
import datetime
import contextlib

class tt_sql():
    def __init__(self, sql_file, header):
        #self.conn = sqlite3.connect(sql_file)
        with contextlib.closing(sqlite3.connect(sql_file)) as self.conn:
            with self.conn:
                with contextlib.closing(self.conn.cursor()) as self.c:
                    self.create_tables()
                    self.insert_rows(header)
                    self.print_table('tt_log')

    def create_tables(self):
        sql_q = """CREATE TABLE IF NOT EXISTS tt_log (
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
        self.c.execute(sql_q)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_offenders (
                id integer PRIMARY KEY,
                ether_addr TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                smb_name TEXT,
                open_ports TEXT,
                num_seen INTEGER
                );"""
        self.c.execute(sql_q)
        self.conn.commit()

    def insert_rows(self, header):
        sql_q = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read) VALUES(?,?,?,?,?,?,?,?)"
        self.c.execute(sql_q, header)
        self.conn.commit()

    def print_table(self, table):
        sql_q = "SELECT * FROM " + table
        self.c.execute(sql_q)
        res = self.c.fetchall()
        print(res)
