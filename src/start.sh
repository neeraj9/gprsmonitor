#! /bin/sh
erl -noinput -detach -sname ensure_epmd_started@localhost -s erlang halt

# Now start the pythonnode
./dsm_oracle_node.py -n dsm_oracle_node@localhost -c cookie \
	 > dsm_oracle_node.log 2 >&1 &
pynode=$!

./dsm_oracle_pdu_node.py -n dsm_oracle_pdu_node@localhost -c cookie \
        > dsm_oracle_pdu_node.log 2 >&1 &
pynode2=$!

./dsm_session_oracle_node.py -n dsm_session_statistics_node@localhost -c cookie \
       > dsm_session_statistics_node.log 2 >&1 &
pynode3=$!

erl -noinput -detach -sname dsm@localhost \
    -setcookie cookie \
    -s dsm start

kill $pynode
kill $pynode2
kill $pynode3
