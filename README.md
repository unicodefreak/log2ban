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
archived log analyser. A firewall system must be used to actually ban an attacker (iptables + ipset, in the example
above).

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

To use blocking lists, please enable the database, process some log records, and then execute

> python log2ban.py print (banned | allbanned)

to print collected IPs to stdout. Specifying "banned" will print only new IPs, while "allbanned" will print every
banned IP, no matter was it previously printed or not.

After the few days the you may wish to unban IPs:

> python log2ban.py print unbanned

This command will print every IP banned before current_time - DAYS_UNBAN, and remove those ip from the DB.

#Installing and integrating with a firewall

(process described for Debian Squeeze 6.0, for other distributions it may vary)

Install ipset:

> sudo apt-get install module-assistant xtables-addons-source

> sudo module-assistant prepare

> sudo module-assistant auto-install xtables-addons-source

> depmod -a

Test that it works

> ipset -L

>

(If you get error messages, like 'Module ip_set not found', then ipset is not installed. Refer to distribution-specific
solutions. Basically the idea is to build ip_set kernel module and load it.).

Install MongoDB, Python and PIP:

> sudo apt-get install mongodb python-pip

Install python dependencies:

> sudo pip install apachelog pexpect pymongo

Clone log2ban somewhere

> git clone git://github.com/jacum/log2ban.git

In log2ban.py, adjust the following parameters:

ECHO_LOG_COMMAND = "tail -f /var/log/nginx/access.log"
This can be any command that feeds log file (preferably, in real time) to log2ban.
If using 'tail', don't forget to restart log2ban every time logs are rotated. Otherwise 'tail' feed stops.

The following is /etc/logrotate.d/nginx, adjust as necessary

    /var/log/nginx/*log {
        daily
        rotate 10
        missingok
        notifempty
        compress
        sharedscripts
        postrotate
            [ ! -f /var/run/nginx.pid ] || kill -USR1 `cat /var/run/nginx.pid`
            /etc/init.d/log2ban stop
            /etc/init.d/log2ban start
        endscript
    }


Install scripts

> sudo mkdir /opt/log2ban

> sudo cp log2ban/log2ban.py /opt/log2ban/

> sudo cp log2ban/ipset-control.sh /opt/log2ban/

> sudo cp log2ban/init-scripts/log2ban-debian.sh /etc/init.d/log2ban

> sudo chmod +x /etc/init.d/log2ban

> sudo chmod +x /opt/log2ban/ipset-control.sh


Start MongoDB

> sudo /etc/init.d/mongodb start

Start log2ban

> sudo /etc/init.d/log2ban start

Add this line to root cron script to update ban lists, e.g. every 5 minutes:
    */5 * * * * /opt/log2ban/ipset_control.sh update

Let it run for a while. Check if any IPs are blocked:

> sudo /opt/log2ban/ipset_control.sh

Now, final thing - connect it all to iptables. Add the following line

> -A INPUT -m set --match-set autoban src -j DROP

to /etc/firewall.conf.

Apply changes:
> sudo /etc/init.d/networking restart

That's about it, enjoy.

# Performance

log2ban is enough fast by itself, but for a very high number of requests CPU usage may become a problem. Consider
disabling logging of requests to static resources, such as images, scripts or style sheets. Further optimization
may include using simpler access log format (csv) instead of using the default one, which is parsed by complicated
apachelog's algorythm based on regular expressions.

# Contacts

Developer: [unicodefreak@gmail.com](mailto:unicodefreak@gmail.com)
