#! /usr/bin/env python

class tt_investigate():
    def __init__(self, sql):
        # Todo: check if investigation is running
        # PID file?
        pid = True
        if(pid):
            sql.set_unread_open()
            #print(sql.get_table('tt_log'))
            #sql.filter_counts('ether_src, ip_src', 'tt_main')

    #def analyze(self):
        # count filters
        # count ether_src within filters
        # write these to tt_swap






























    ##  Return tuple of headers for each filter
    #def filter_dict(self, rows):
    #    ip_filter = {'icmp-echo': (),
    #                 'tcp-syn': (),
    #                 'tcp-fin': ()}
    #    for row in rows:
    #        for key in ip_filter:
    #            if row['filter'] == key:
    #                ip_filter[key] = ip_filter[key] + (row,)
    #    return ip_filter
