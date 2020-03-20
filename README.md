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
    * Class inheritence?

* SQL Analysis
    * PID lock for investigator?  Check swp for ether src being worked on, if so blacklist it from analysis.
    * When tt is touched it port scans/smb lookup and monitors changes after 30 seconds and 5 minutes.  sending email each time
    * Check if swap is empty, may indicate an ongoing investigation
    
    * Create ticket no to tt log to indicate which ticket number this instance is working on.
    * Count open by filter
    * For each filter select count of each 'ether src', 'ip src'
    * Check if ether src exists on offenders, if not insert data with times seen set to 1.  port scan, smb name set to 'None'
    * Write ether datetime, src ether, ip src, filter, occurs to swap
    * Start port scan and smb lookup
    * Check if any changes since first investigation, if so write logic to determine if a single ping or recurse sleeping 5
        *  times n minutes until pings stop.  report when pings stops.  if single ping report the single ping 
    * Do same sort of thing for tcp syn connections, indicating a port scan
    * Evaluate what tcp fin packets were sent, indicating a handshake ended.  report which ports
    * Sleep 30 seconds
    * Select from unread data only unopened related ether src for this ticket.
    * Call investigator recursively sending ticket id along
    * Compare unread packets with ticket id related packets
    * Send email report
    * If new do analysis on number of pings (if they stopped), port scan and tcp-fin connection
    * Sleep 5 minutes
    * Call investigator recurseively sending ticket id along
    * If changes send final email with the number of tcp syn connections and on which ports, number of pings, smb name, open ports, number of successful handshakes and on which ports
    * Clear swap space of all rows with current ticket id
