#! /bin/sh
erl -noinput -detach -sname ensure_epmd_started@localhost -s erlang halt


./dsm_packet_node.py -n dsm_packet_node@localhost -c cookie \
       > dsm_packet_node.log 2 >&1 &
pynode3=$!

erl -noinput -detach -sname dsm@localhost \
    -setcookie cookie \
    -s dsm start

kill $pynode3
