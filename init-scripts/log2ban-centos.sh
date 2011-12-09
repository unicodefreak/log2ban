#!/bin/bash
#
# chkconfig: - 92 08
# description: Fail2ban daemon
#              http://fail2ban.sourceforge.net/wiki/index.php/Main_Page
# process name: fail2ban-server
#
#
# Author: Tyler Owen
#

# Source function library.
. /etc/init.d/functions

# Check that the config file exists
# [ -f /etc/fail2ban/fail2ban.conf ] || exit 0

LOG2BAN="python26 /root/log2ban/log2ban.py"

RETVAL=0

getpid() {
    #pid=`ps -eo pid,comm | grep log2ban- | awk '{ print $1 }'`
    pid=`ps ax | grep log2ban | grep python | awk '{ print $1 }'`
}

start() {
    echo -n $"Starting log2ban: "
    getpid
    if [ -z "$pid" ]; then
        $LOG2BAN &
    fi
    getpid
    if [ -n "$pid" ]; then
        touch /var/lock/subsys/log2ban
        echo_success
    else
        echo_failure
    fi
    echo
    return $RETVAL
}

stop() {
    echo -n $"Stopping log2ban: "
    getpid
    RETVAL=$?
    if [ -n "$pid" ]; then
        kill $pid
        killall tail
# $LOG2BAN stop > /dev/null
    sleep 1
    getpid

    if [ -z "$pid" ]; then
        rm -f /var/lock/subsys/log2ban
        echo_success
    else
        echo_failure
    fi
    else
        echo_failure
    fi
    echo
    return $RETVAL
}

# See how we were called.
case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  unbanned)
        getpid
        if [ -n "$pid" ]; then
                $LOG2BAN print unbanned
        fi
        ;;
  banned)
        getpid
        if [ -n "$pid" ]; then
                $LOG2BAN print banned
        fi
        ;;

  status)
        getpid
        if [ -n "$pid" ]; then
                echo "Log2ban (pid $pid) is running..."
        else
                RETVAL=1
                echo "Log2ban is stopped"
        fi
        ;;
  restart)
        stop
        start
        ;;
  *)
        echo $"Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac

exit $RETVAL
