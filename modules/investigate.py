#! /usr/bin/env python

import sqlite3
import contextlib

class tt_investigate():
    def __init__(self, sql_file):
        # Todo: check if investigation is running
        # PID file?
        pid = True
        if(pid):
            with contextlib.closing(sqlite3.connect(sql_file)) as conn:
                with conn:
                    with contextlib.closing(conn.cursor()) as self.c:
                        open_rows = self.open_rows()
                        f_dict = self.filter_dict(open_rows)
                        self.analyze(f_dict)

    # Analyze data
    def analyze(self, f_dict):
        for key in f_dict:
            print(f_dict[key])
            # iterate through keys
            # create sql table scratchpad
            # record what is found on that table
            # wait 30 seconds
            # analyze again


    # Set read to 'open' and return open rows
    def open_rows(self):
        sql_q = "UPDATE tt_main SET read = 'open' WHERE read = 'unread'"
        self.c.execute(sql_q)
        sql_q = "SELECT * FROM tt_main WHERE read = 'open';"
        self.c.execute(sql_q)
        rows = self.c.fetchall()
        # Create dictionary of SQL column to header value
        table_col = ('id','datetime','filter','ether_src','ip_src','ip_dst','tcp_src','tcp_dst','read')
        sql_d = ()
        for row in range(len(rows)):
            sql_d += (dict(zip((table_col),(rows[row]))),)
        return sql_d

    #  Return tuple of headers for each filter
    def filter_dict(self, rows):
        ip_filter = {'icmp-echo': (),
                     'tcp-syn': (),
                     'tcp-fin': ()}
        for row in rows:
            for key in ip_filter:
                if row['filter'] == key:
                    ip_filter[key] = ip_filter[key] + (row,)
        return ip_filter

    # Read all unread rows
    def do_read(self):
        sql_q = "UPDATE tt_main SET read = 'read' WHERE read = 'open'"
        self.c.execute(sql_q)
