#! /usr/bin/env python

import sqlite3
import contextlib

class tt_investigate():
    def __init__(self, sql_file):
        # Todo: check if investigation is running
        with contextlib.closing(sqlite3.connect(sql_file)) as conn:
            with conn:
                with contextlib.closing(conn.cursor()) as self.c:
                    sql_q = "SELECT * FROM tt_log WHERE read=FALSE;"
                    self.c.execute(sql_q)
                    print(self.c.fetchall())

