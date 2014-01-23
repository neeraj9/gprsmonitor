#! /usr/bin/python
# To change this template, choose Tools | Templates
# and open the template in the editor.
__author__="kebo"
__date__ ="$2009-11-16 14:05:55$"
import sys
import getopt
import string
import cx_Oracle
from py_interface import erl_node
from py_interface import erl_opts
from py_interface import erl_eventhandler
db = cx_Oracle.connect('dsm', 'dsm', 'localhost:1521/dsmdb')
db.autocommit = True
counter = 0

m=None

n=None

def _TestMBoxRPCResponse(msg):
    print "hello"

def __TestMBoxCallback(msg):
   global counter
   global db
   counter +=1
   cur = db.cursor()
   #print msg
   roam_in = 0
   if string.find(msg[0],"+86") == -1 :
   	roam_in = 1
   cur.execute("insert into stat_session(id,msisdn,teid_i,teid,end_user_addr, begin_time, end_time,upload,download,session_duration,apn,roam_in) values(stat_session_seq.nextval,:a,:b,:c,:d,:e,:f,:g,:h,:i,:j,:k)",{'a':msg[0],'b':msg[1],'c':msg[2],'d':msg[3],'e':msg[4][0],'f':msg[5][0],'g':msg[6],'h':msg[7],'i':msg[8],'j':msg[9],'k':roam_in})


def main(argv):
    global m
    try:
        opts, args = getopt.getopt(argv[1:], "?n:c:")
    except getopt.error, info:
        print info
        sys.exit(1)

    hostName = "localhost"
    ownNodeName = "dsm_session_statistics_node"
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

