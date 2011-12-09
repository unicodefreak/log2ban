#!/bin/bash

DAEMON=/usr/bin/python
ARGS="/opt/log2ban/log2ban.py"
PIDFILE=/var/run/log2ban.pid
USER=www-data
GROUP=www-data
LOG2BAN="$DAEMON $ARGS"

getpid() {
    pid=`cat $PIDFILE`
    # pid=`ps ax | grep log2ban | grep python | awk '{ print $1 }'`
}

case "$1" in
  start)
    echo "Starting server"
    /sbin/start-stop-daemon --start --pidfile $PIDFILE \
        --user $USER --group $GROUP \
        -b --make-pidfile \
        --chuid $USER \
        --exec $DAEMON $ARGS
    ;;
  stop)
    echo "Stopping server"
    /sbin/start-stop-daemon --stop --pidfile $PIDFILE --verbose
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
  allbanned)
        getpid
        if [ -n "$pid" ]; then
                $LOG2BAN print allbanned
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
  *)
    echo "Usage: /etc/init.d/log2ban {start|stop|status|banned|unbanned|allbanned}"
    exit 1
    ;;

esac

exit 0


