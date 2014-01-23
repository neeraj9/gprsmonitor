#!/usr/bin/python
import sys
import getopt
import cx_Oracle
import os

from py_interface import erl_node
from py_interface import erl_opts
from py_interface import erl_eventhandler
db = cx_Oracle.connect('dsm', 'dsm', 'localhost:1521/dsmdb')
db.autocommit = False
counter = 0

def __TestMBoxCallback(msg):
   global counter
   global db
   counter +=1
   cur = db.cursor()
   #print "msg=%s" % `msg`
   cur.execute("insert into test_packet_offset(no,offset,len,filename) values(:a,:b,:c,:d)",{'a':msg[0],'b':msg[1],'c':msg[2],'d':msg[3]})
   if counter == 1000:
  	 db.commit()
         counter = 0


def TimeOutEventCallback( *msg):
	db.commit()
        #print "timeout........."
        msg[0].AddTimerEvent(0.1,TimeOutEventCallback,msg[0])
n=None
m=None

def main(argv):
    try:
        opts, args = getopt.getopt(argv[1:], "?n:c:")
    except getopt.error, info:
        print info
        sys.exit(1)

    hostName = "localhost"
    ownNodeName = "dsm_packet_node"
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
    evhand.AddTimerEvent(0.4,TimeOutEventCallback,evhand)
    evhand.Loop()
    db.close()

main(sys.argv)
