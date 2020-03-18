#! /usr/bin/env python

import sqlite3
import pandas as pd

class tt_sql():
    def __init__(self, sql_file):
        with contextlib.closing(sqlite3.connect(sql_file)) as conn:
	    with conn:
		with contextlib.closing(conn.cursor()) as self.c:
                    pass

