#! /usr/bin/env python

import sqlite3

class tt_sql():
    def __init__(self):
        sql_file = 'db/tt.db'
        self.conn = sqlite3.connect(sql_file)
        self.create_tables()

    def create_tables(self):
        try:
            c = self.conn.cursor()
            sql = """CREATE TABLE IF NOT EXISTS tt_log (
                    id INTEGER PRIMARY KEY,
                    datetime TIMESTAMP NOT NULL,
                    filter TEXT NOT NULL,
                    ether_src TEXT NOT NULL,
                    ip_src TEXT NOT NULL,
                    ip_dst TEXT NOT NULL,
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
        except:
            print("Error of some sort")
        finally:
            c.close()

    def insert_rows(self, l_filter):
        c = self.conn.cursor()
        if self.filter['sniff_filter'] == 'icmp-echo':
            sql = """INSERT INTO tt_log(
                    datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read
                    ) VALUES(?,?,?,?,?,?,?,?)"""
            c.execute(sql, (l_filter['sniff_filter'],
                            l_filter['ether_src'],
                            l_filter['ip_src'],
                            l_filter['ip_dst'],
                            l_filter['tcp_src'],
                            l_filter['tdp_dst'],
                            'FALSE'))
        self.conn.commit()
        c.close()



