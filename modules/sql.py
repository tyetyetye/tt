#! /usr/bin/env python

import sqlite3
import pandas as pd
from sqlalchemy import create_engine
from pandas.io import sql

class tt_sql():
    def __init__(self):
        self.sql_file = 'db/tt.db'
        self.engine = create_engine('sqlite:////home/jtye/tt/db/tt.db')

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
                read TEXT
                );"""
        sql.execute(sql_q, self.engine)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_swap (
                id INTEGER PRIMARY KEY,
                dateteime TIMESTAMP,
                filter TEXT,
                ether_src TEXT,
                ip_src TEXT,
                n_packets INTEGER,
                incident_id INTEGER
                );"""
        sql.execute(sql_q, self.engine)
        sql_q = """CREATE TABLE IF NOT EXISTS tt_devicelist (
                id integer PRIMARY KEY,
                ether_addr TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                smb_name TEXT,
                open_ports TEXT,
                num_seen INTEGER
                );"""
        sql.execute(sql_q, self.engine)
    def sql_query(self, sql_q):
        data = pd.read_sql_query(sql_q, self.engine, index_col='id')
        return data


    def set_unread_open(self):
        sql_q = "UPDATE tt_log SET read = 'open' WHERE read = 'unread'"
        sql.execute(sql_q, self.engine)
        sql_q = "SELECT * from tt_log WHERE read = 'open'"
        return sql_query(data)

    def insert_row_header(self, header):
        sql_q = "INSERT INTO tt_log(datetime, filter, ether_src, ip_src, ip_dst, tcp_src, tcp_dst, read) VALUES(?,?,?,?,?,?,?,?)"
        sql.execute(sql_q, self.engine, params=header)

    def get_table(self, table):
        data = pd.read_sql_table(table, self.engine, index_col='id')
        return data

    def by_filter(self, columns, table):
        filters = ['icmp-echo', 'tcp-fin', 'tcp-syn']
        sql_t = "SELECT " + columns + " FROM " + table + " WHERE filter = '"
        for f in range(len(filters)):
            sql_q = sql_t + filters[f] + "';"
            data = pd.read_sql_query(sql_q, self.engine, index_col='id'

