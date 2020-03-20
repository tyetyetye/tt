#! /usr/bin/env python

import time

class tt_investigate():
    def __init__(self, sql):
        if sql.set_unread_open():
            time.sleep(30)
            # set unread open for new rows that match ether_src of current incident id
        else:
            pass
