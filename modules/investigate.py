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
                        self.analysis(unread_rows)

    # Get all unread rows
    def get_unread(self):
        sql_q = "SELECT * FROM tt_log WHERE read=FALSE;"
        self.c.execute(sql_q)
        return(self.c.fetchall())

    # Read all unread rows
    def do_read(self):
        sql_q = "UPDATE tt_log SET read = True WHERE read = FALSE"
        self.c.execute(sql_q)

    def analysis(self, rows):
        for row in rows:
            print(row[2])
