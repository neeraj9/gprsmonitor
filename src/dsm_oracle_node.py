#!/usr/bin/python
import sys
import getopt
import cx_Oracle
import os

from py_interface import erl_node
from py_interface import erl_opts
from py_interface import erl_eventhandler
db = cx_Oracle.connect('dsm', 'dsm', 'localhost:1521/dsmdb')
db.autocommit = True
m=None
n=None

def __TestMBoxCallback(msg):
   global counter
   global db
   cur = db.cursor()
   #print "msg=%s" % `msg`
   if msg[0] == "create" :
        cur.execute("insert into sdr_create_pdp1(req_time,resp_time,seq_no,src_ip,src_port,des_ip,des_port,cause,apn,msisdn,end_user_addr, \
        req_frame, resp_frame,req_filepath,req_offset,resp_filepath,resp_offset) \
        values(:a,:b,:c,:d,:e,:f,:g,:h,:i,:j,:k,:l,:m,:n,:o,:p,:q)",\
        {'a':msg[1][0],'b':msg[2][0],'c':msg[3],'d':msg[4],'e':msg[5],'f':msg[6],'g':msg[7], \
        'h':msg[8],'i':msg[9],'j':msg[10],'k':msg[11],'l':msg[12],'m':msg[13],'n':msg[14],'o':msg[15],'p':msg[16],'q':msg[17]})
   elif msg[0] == "delete":
        cur.execute("insert into sdr_delete_pdp1(req_frame,req_offset,req_filepath,req_time,\
        resp_frame,resp_offset,resp_filepath,resp_time,seq_no, \
        src_ip,src_port,des_ip,des_port,cause,teid) \
        values(:a,:b,:c,:d,:e,:f,:g,:h,:i,:j,:k,:l,:m,:n,:o)",\
        {'a':msg[1],'b':msg[2],'c':msg[3],'d':msg[4][0],'e':msg[5],'f':msg[6],'g':msg[7], \
        'h':msg[8][0],'i':msg[9],'j':msg[10],'k':msg[11],'l':msg[12],'m':msg[13],'n':msg[14],'o':msg[15]})
   elif msg[0] == "update" :
        cur.execute("insert into sdr_update_pdp1(req_frame,req_offset,req_filepath,req_time,\
        resp_frame,resp_offset,resp_filepath,resp_time,seq_no, \
        src_ip,src_port,des_ip,des_port,cause,teid) \
        values(:a,:b,:c,:d,:e,:f,:g,:h,:i,:j,:k,:l,:m,:n,:o)",\
        {'a':msg[1],'b':msg[2],'c':msg[3],'d':msg[4][0],'e':msg[5],'f':msg[6],'g':msg[7], \
        'h':msg[8][0],'i':msg[9],'j':msg[10],'k':msg[11],'l':msg[12],'m':msg[13],'n':msg[14],'o':msg[15]})
    elif msg[0] == "dns_req_resp" :
        cur.execute("insert into sdr_dns_query(req_frame, req_time, resp_frame, \
        resp_time, seq_no, src_ip, src_port, des_ip, des_port, cause, delay_time, \
        domain_name, iplist) values (:a,:b,:c,:d, \
        :e,:f,:g,:h,:i,;j,:k, \
        :l,:m)",\
        {'a':msg[1],'b':msg[2][0],'c':msg[3],'d':msg[4][0],'e':msg[5],'f':msg[6],'g':msg[7], \
        'h':msg[8],'i':msg[9],'j':msg[10],'k':msg[11],'l':msg[12],'m':msg[13]})


def main(argv):
    global m
    try:
        opts, args = getopt.getopt(argv[1:], "?n:c:")
    except getopt.error, info:
        print info
        sys.exit(1)

    hostName = "localhost"
    ownNodeName = "dsm_oracle_node"
    cookie = "cookie"

    for (optchar, optarg) in opts:
        if optchar == "-?":
            print "Usage: %s erlnode" % argv[0]
            sys.exit(1)
        elif optchar == "-c":
            cookie = optarg
        elif optchar == "-n":
            ownNodeName = optarg

    print "Creating node..."
    n = erl_node.ErlNode(ownNodeName, erl_opts.ErlNodeOpts(cookie=cookie))
    print "Publishing node..."
    n.Publish()
    print "Creating mbox..."
    m = n.CreateMBox(__TestMBoxCallback)
    print "Registering mbox as p..."
    m.RegisterName("db")

    print "Looping..."
    evhand = erl_eventhandler.GetEventHandler()
    evhand.Loop()
    db.close()

main(sys.argv)
