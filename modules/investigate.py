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
                        rows = self.rows_dict(open_rows)
                        counts = self.filter_counts(rows)

    # Count filter occurences
    def filter_counts(self, rows):
        count_dict = {'icmp-echo': 0,
                  'tcp-syn': 0,
                  'tcp-fin': 0}
        for row in range(len(rows)):
            for key in count_dict:
                if rows[row]['filter'] == key:
                    count_dict[key] = count_dict[key] + 1
        return count_dict



    # Set read to 'open' and return open rows
    def open_rows(self):
        sql_q = "UPDATE tt_log SET read = 'open' WHERE read = 'unread'"
        self.c.execute(sql_q)
        sql_q = "SELECT * FROM tt_log WHERE read = 'open';"
        self.c.execute(sql_q)
        return(self.c.fetchall())

    # Read all unread rows
    def do_read(self):
        sql_q = "UPDATE tt_log SET read = 'read' WHERE read = 'open'"
        self.c.execute(sql_q)

    def rows_dict(self, rows):
        # Human callable dictionary names for SQL columns
        # Format to a tuple of dictionaries
        table_col = ('id','datetime','filter','ether_src','ip_src','ip_dst','tcp_src','tcp_dst','read')
        sql_t = ()
        for row in range(len(rows)):
            sql_t += (dict(zip((table_col),(rows[row]))),)
        return(sql_t)



