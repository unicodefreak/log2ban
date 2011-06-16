#About

This program allows detection and banning of IPs participating in DDOS or bruteforce attack to the webserver.

Such kind of attack is characterized by a high number of similar requests from a relatively small subset of IPs in
a short period of time.

#How log2ban works

For detection, each request to the server is marked with an identifier made from request properties (for example,
from IP and request URL: "1.2.3.4/login.php"). When the number of hits with a certain ID reaches tolerance
margin within a detection window, client IP is sent as an argument to the external command (BAN_IP_COMMAND) or
collected for batch blocking (see "Blocking Lists").

Log2ban is limited to operating on websever's access log in the realtime, and is not intended to be used as
archived log analyser. A firewall system must be used to actually ban an attacker.

The script reads access log in the realtime, using 'tail -n 1 -f' or similar command, as specified in the
configuration. If command sends EOF, log2ban will terminate. If command will stop writing log records to the
stdout, log2ban will hang forever.

#Tuning

Default Apache/nginx access log pattern is supported from the box. Modifications made to the default format must be
reflected in ACCESS_LOG_RECORD_FORMAT variable.

Detection policy may be tuned. The most important parameter is TOLERANCE_MARGIN. The second-most-important are
WINDOW_SIZE and SLOT_INTERVAL. Shorter interval and increased size means better detection (and worse performance).

To change ID assignment policy, modify "create_server_hit_id" function.

To for record skipping criteria, modify "skip" function. Currently, requests to several static file types are
skipped from processing.

#Blocking Lists

To use blocking lists, please enable the DB, process some log records, and then execute

> python log2ban.py print (banned | allbanned)

to print collected IPs to stdout. Specifying "banned" will print only new IPs, while "allbanned" will print every
banned IP, no matter was it previously printed or not.

After the few days the you may wish to unban IPs:

> python log2ban.py print unbanned

This command will print every IP banned before current_time - DAYS_UNBAN, and remove those ip from the DB.

# Performance

log2ban is enough fast by itself, but for a very high number of requests CPU usage may become a problem. Consider
disabling logging of requests to static resources, such as images, scripts or style sheets. Further optimization
may include using simpler access log format (csv) instead of using the default one, which is parsed by complicated
apachelog's algorythm based on regular expressions.

# Contacts

Developer: [unicodefreak@gmail.com](mailto:unicodefreak@gmail.com)
