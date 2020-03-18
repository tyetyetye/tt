Tattle Tale (tt)

Utilizes scapy and sqlite3

* About:
    * Listens for packets matching definable filters and logs to sqlite3 database
    * Maintains a table of offending MAC addresses including incident ID
    * Investigates offenders:
        * OS fingerprint guess
        * Open ports
        * SMB client information
        * Vuln scanning of offender
    * 30 seconds, 5 minutes after offense, creates reports of activity of offending MAC/IP address
    * Reports to configurable email address and SNMP traps
    * Once a packet is filtered pull all unread rows from SQL log:
        * How many ICMP requests?
        * What type of filters and how many?
        * Wait 30 seconds and analyze again
        * Compare 30 second analysis
        * Get info on remote machine

* TODO:
    * TCP socket listen traps
    * configure packet filters for TCP socket traps
    * UDP filters?
    * Investigator including portscan, OS detection, possibly vuln scanner?
        * SMB info collector
    * Reporting
    * Investigator uses IPC or PID monitoring?
