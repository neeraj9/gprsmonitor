#! /usr/bin/python

__author__="dell"
__date__ ="$2009-10-14 16:57:57$"
import cx_Oracle
import os
import sigar
sg = sigar.open()
mem = sg.mem()
swap = sg.swap()
cpu = sg.cpu()
sg.close()
mem_total = mem.total()/1024
mem_used = mem.used()/1024
mem_free = mem.free()/1024

swap_total = swap.total()/1024
swap_used = swap.used() / 1024
swap_free = swap.free() / 1024

cpu_user = cpu.user()/1024
cpu_sys = cpu.sys()/1024
cpu_idle = cpu.idle()/1024

db = cx_Oracle.connect('dsm', 'dsm', 'localhost:1521/dsmdb')
db.autocommit = True
cur = db.cursor()
cur.execute("insert into stat_computer_monitor(id,name,mem_total,mem_used,mem_free,swap_total,swap_used,swap_free,cpu_us,cpu_sy,cpu_id,create_time) VALUES(STAT_COMPUTER_MONITOR_SEQ.NEXTVAL, 'oracledb',:a,:b,:c,:d,:e,:f,:g,:h,:i,sysdate)",{'a':mem_total,'b':mem_used,'c':mem_free,'d':swap_total,'e':swap_used,'f':swap_free,'g':cpu_user,'h':cpu_sys,'i':cpu_idle})
db.close



if __name__ == "__main__":
    print "Hello World";
