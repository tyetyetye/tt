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
                        unread_rows = self.get_unread()
                        #self.do_read()
                        rows = self.rows_dict(unread_rows)
                        print(rows)
                        #self.process(rows)

    # Get all unread rows
    def get_unread(self):
        sql_q = "SELECT * FROM tt_log WHERE read=FALSE;"
        self.c.execute(sql_q)
        return(self.c.fetchall())

    # Read all unread rows
    def do_read(self):
        sql_q = "UPDATE tt_log SET read = True WHERE read = FALSE"
        self.c.execute(sql_q)

    def rows_dict(self, rows):
        # Dictionarize SQL rows
        table_map = {0: 'id',
                     1: 'datetime',
                     2: 'filter',
                     3: 'ether_src',
                     4: 'ip_src',
                     5: 'ip_dst',
                     6: 'tcp_src',
                     7: 'tcp_dst',
                     8: 'read'
                     }
        sql_dict = {}
        d_sql = {}
        dd_sql = {}
        for row in range(len(rows)):
            sql_dict[row] = rows[row]
            for items in range(len(sql_dict[row])):
                a = table_map[items]
                d_sql[a] = sql_dict[row][items]
            sql_dict[row] = d_sql
        return(sql_dict)



