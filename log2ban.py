# Copyright 2011 Ilya Brodotsky
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
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

"""

__version__ = "1.0"
__license__ = """http://www.apache.org/licenses/LICENSE-2.0"""
__author__ = "Ilya Brodotsky <unicodefreak@gmail.com>"
__contributors__ = [
]

from datetime import datetime, timedelta
import subprocess
from time import time
import logging
import sys

try:
    from apachelog import parser
    import pexpect
except ImportError, e:
    raise ImportError (str(e) + """
    Please install apachelog and pexpect modules (using the command 'sudo pip install apachelog pexpect')""")

#
# Shell command to execute for banned ip. Set to None to disable command
# If database is enabled, the command will be executed only for new (not currently banned) ips.
# Otherwise, the command may be called repeatedly for the same ip
#
BAN_IP_COMMAND = "echo \"%s\" >> /tmp/banlist.txt" # %s is substituted with ip, None for no command 

#
# Shell command used for echoing log file records in the realtime, line by line. Executed once when log2ban starts
#
ECHO_LOG_COMMAND = "python sleepdump.py" # shell command 

#
# Length of a single slot used to catch server hits, in milliseconds
#
SLOT_INTERVAL = 1000 # millis

#
# Total number of slots in time window
#
WINDOW_SIZE = 60 # slots

#
# How many server hits needed to ban the ip
#
TOLERANCE_MARGIN = 100 # hits in the window

#
# Standard apache log
#
ACCESS_LOG_RECORD_FORMAT = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'

#
# Database connection properties. Set MONGODB_HOST to None to disable database
#
MONGODB_HOST = "localhost" # None to disable database connection
MONGODB_PORT = 27017
MONGODB_DB = 'log2ban'

#
# Unban ip after the specified number of days
#
DAYS_UNBAN = 7

#
# Database collection which is holding currently banned ips
#
banned_ip_collection = None
if MONGODB_HOST: # if db is enabled
    try:
        from pymongo import Connection
    except ImportError, e:
        raise ImportError (str(e) + """
        Please install MongoDB and pymongo package (using the command 'sudo pip install pymongo').
        If you are not willing to use the database, please set MONGODB_HOST to None""")

    banned_ip_collection = Connection(MONGODB_HOST, MONGODB_PORT)[MONGODB_DB].banned

#
# Internal logging setup
#
INTERNAL_LOG_PATTERN = '%(asctime)s %(filename)s/%(funcName)s: %(message)s' 
INTERNAL_LOG_FILE = "/var/log/log2ban.log" # None to turn off logging to file

logging.basicConfig(format=INTERNAL_LOG_PATTERN, level=logging.DEBUG)
logger = logging.getLogger()
if INTERNAL_LOG_FILE:
    file_handler = logging.FileHandler(INTERNAL_LOG_FILE)
    logger.addHandler(file_handler)

def new_log_record_handler(line):
    """Called on new log line
    """
    global window
    global millis

    parsed_logrecord = logrecord(line)
    if not parsed_logrecord:
        return
    if skip(parsed_logrecord):
        return
    hit_id = create_server_hit_id(parsed_logrecord)
    if not hit_id:
        return

    (cdate, ctime, ip, url, agent, referrer, code) = parsed_logrecord

    if hit_id in window[-1]:
        window[-1][hit_id]["hits"] += 1
        window[-1][hit_id]["ip"] = ip
    else:
        window[-1][hit_id] = {}
        window[-1][hit_id]["hits"] = 1
        window[-1][hit_id]["ip"] = ip

    current_millis = long(time() * 1000)
    delta = current_millis - millis
    if (delta / SLOT_INTERVAL) > WINDOW_SIZE:
        delta = WINDOW_SIZE * SLOT_INTERVAL
    while delta >= SLOT_INTERVAL:
        delta -= SLOT_INTERVAL
        slot = window.pop(0)
        for k in slot:
            hits = slot[k]["hits"]
            for wslot in window:
                if k in wslot:
                    hits += wslot[k]["hits"]
            if hits > TOLERANCE_MARGIN:
                banip(slot[k]["ip"], "Banning ip: %s, hit tolerance margin overcome with %d hits" % (slot[k]["ip"], hits))
        window.append({})
        millis = current_millis

def banip(ip, reason):
    """Called to ban an ip
    """
    if not ip:
        return

    if BAN_IP_COMMAND and not is_ip_banned(ip): # if command is set and (ip is not found in db OR db is not available)
        logger.info(reason)
        logger.info("Executing " + BAN_IP_COMMAND % ip)
        subprocess.call([BAN_IP_COMMAND % ip,], shell=True)
    if banned_ip_collection:
        # ban time is silently updated in db 
        entry = {
            "_id" : ip,
            "ban_time" : datetime.now(),
            "printed" : "no" # "printed" flag is cleared
        }
        banned_ip_collection.update(spec={"_id" : ip}, document=entry, upsert=True)

def is_ip_banned(ip):
    if not banned_ip_collection:
        return False
    return banned_ip_collection.find_one({"_id" : ip}) is not None

window = None # list of slots, shifting every SLOT_INTERVAL milliseconds
millis = None # last window shift, milliseconds from epoch

logline_parser = parser(ACCESS_LOG_RECORD_FORMAT) # see apachelog docs for details 

def logrecord(logline):
    """Parse log line
       Returns values as tuple: (date, time, ip, url, agent, referrer,)
    """

    (date, time, ip, url, agent, referrer, code) = (None, None, None, None, None, None, None)

    try:
        if logline.count('"') == 8: # remove the misterious last "-"
            logline = logline[:len(logline) - 3]
        parsed = logline_parser.parse(logline)

        code = parsed["%>s"]
        ip = parsed["%h"]
        # empty request
        if not len(parsed["%r"]) or parsed["%r"] == "-":
            url = "-"
        else:
            url = parsed["%r"].split(" ")[1]
    except Exception,e:
        logger.error("Exception while parsing log record '%s', exception message is '%s'" % (logline, e.message,))
        return None

    return date, time, ip, url, agent, referrer, code

def skip(logrecord):
    """True if record should be skipped
    """
    (date, time, ip, url, agent, referrer, code) = logrecord

    if url == "-":
        return True
    elif url.endswith(".gif") or url.endswith(".jgp") or url.endswith(".css") or url.endswith(".png") or url.endswith(".js"):
        return True
    elif code == '304':
        return True
    else:
        return False

def create_server_hit_id(logrecord):
    """Create unique id of web server hit
    """
    (date, time, ip, url, agent, referrer, code) = logrecord

    if not ip or not url:
        logger.error("Not all required parameters present in logrecord %s" % logrecord)
        return None
    else:
        return ip + url

def access(new_log_record_callable):
    """Process output of ECHO_LOG_COMMAND
    """
    #p = pexpect.spawn("tail -n 1 -f ./sources/all.txt", timeout=None)
    logger.info("Echoing log file via '%s' command." % ECHO_LOG_COMMAND)

    p = pexpect.spawn(ECHO_LOG_COMMAND, timeout=None)
    while p.isalive():
        new_log_record_callable(p.readline().rstrip())

    logger.info("Finishing echoing log file.")

def print_fresh_banned_ips():
    """Print banned ips
    """
    logger.info("Printing banned ips to stdout")
    
    for entry in banned_ip_collection.find({"printed" : "no"}):
        ip = entry["_id"]

        logger.info("Printing '%s' to stdout" % ip)
        # print to stdout
        print ip
        
        banned_ip_collection.update(spec={"_id" : ip}, document={"$set" : {"printed" : "yes"}})

def print_all_banned_ips():
    """Print all banned ips
    """
    logger.info("Printing all banned ips to stdout")

    for entry in banned_ip_collection.find({}):
        ip = entry["_id"]

        logger.info("Printing '%s' to stdout" % ip)
        # print to stdout
        print ip

def dumb_ips_for_unban():
    """Print banned ips are older than UNBAN_DAYS
    """
    logger.info("Printing unbanning ips to stdout")

    unban_time = datetime.now() - timedelta(days=DAYS_UNBAN)
    for entry in banned_ip_collection.find(spec={"ban_time" : {"$lt" : unban_time}}):
        ip = entry["_id"]

        logger.info("Printing '%s' to stdout" % ip)
        # print to stdout
        print ip

        banned_ip_collection.remove(spec={"_id" : ip})

def unban_ip(ip):
    """Remove banned ip from the db
    """
    banned_ip_collection.remove(spec={"_id" : ip})

if __name__ == "__main__":
    if len(sys.argv) == 1:
        logger.info("Started with no arguments.")
        window = [{} for x in range(WINDOW_SIZE)]
        millis = long(time() * 1000)
        access(new_log_record_handler)
    if len(sys.argv) == 3:
        command = sys.argv[1]
        arg = sys.argv[2]
        if command == "print":
            if arg == "banned":
                print_fresh_banned_ips()
            elif arg == "allbanned":
                print_all_banned_ips()
            elif arg == "unbanned":
                dumb_ips_for_unban()
        elif command == "unban":
            unban_ip(arg)
        else:
            logger.error("Unknown command '%s'" % command)
    else:
        logger.error("Invalid command line")