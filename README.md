Tattle Tale (tt)

Utilizes scapy and sqlite3

* Listens for packets matching definable filters and logs to sqlite3 database
* Maintains a table of offending MAC addresses including incident ID
* Investigates offenders:
    * OS fingerprint guess
    * Open ports
* 30 seconds, 5 minutes after offense, creates reports of activity of offending MAC/IP address
* Reports to configurable email address and SNMP traps
