#!/bin/sh
ipset=`which ipset`
SET=autoban

case "$1" in
  init)
    $ipset -X $SET
    $ipset -N $SET iphash
    ;;

  update)
    for i in `/etc/init.d/log2ban banned`; do
        $ipset -A $SET $i;
    done;

    for i in `/etc/init.d/log2ban unbanned`; do
        $ipset -D $SET $i;
    done;
    ;;

  reset)
    $ipset -F autoban $i;
    for i in `/etc/init.d/log2ban allbanned`; do
        $ipset -A $SET $i;
    done;
    ;;

  list)
    $ipset -L $SET
    ;;

  *)
    echo "Usage: ipset-control.sh {init|update|reset|list}"
    exit 1
    ;;
esac
