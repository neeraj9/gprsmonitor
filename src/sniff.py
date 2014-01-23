#! /usr/bin/python
__author__="kebo"
__date__ ="$2009-11-5 11:15:55$"
import pcap
import sys
import string
import time
import socket
import struct
import getopt

protocols={socket.IPPROTO_TCP:'tcp',
           socket.IPPROTO_UDP:'udp',
           socket.IPPROTO_ICMP:'icmp'}

node = None
mb = None
decoder = None

def send(payload):
    sz = len(payload)
    header= struct.pack("!h", sz)
    return sys.stdout.write( header + payload )

def print_packet(pktlen, data, timestamp):
    global mb
    if not data:
        return
    #send(data)
    #print data
    #print timestamp
    print '\n%s.%f' % (time.strftime('%H:%M',time.localtime(timestamp)),timestamp % 60)

if __name__=='__main__':
    p = pcap.pcapObject()
    #dev = pcap.lookupdev()
    dev = "eth0"
    net, mask = pcap.lookupnet(dev)
    # note:  to_ms does nothing on linux
    p.open_live(dev, 1600, 0, 100)
    #p.dump_open('dumpfile')
    p.setfilter(string.join(["tcp","port 22"],' '), 0, 0)
    # try-except block to catch keyboard interrupt.  Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    #p.setnonblock(1)
    try:
        while 1:
            p.dispatch(1, print_packet)
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()



