#!/usr/bin/python

# Author: José Castillo Lema <josecastillolema@gmail.com>

import sys
import dpkt

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

f_in  = open(sys.argv[1],'r')
f_out = open(sys.argv[1]+'_fixed','wb')

pcap = dpkt.pcap.Reader(f_in)
pcap2 = dpkt.pcap.Writer(f_out)

#for ts, pkt in pcap:
for buff in pcap:
    (ts, pkt) = buff
    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue

    ipcounter+=1

    if eth.data.p==dpkt.ip.IP_PROTO_TCP: 
       tcpcounter+=1

    if eth.data.p==dpkt.ip.IP_PROTO_UDP:
       udpcounter+=1

       #print 'AKI ', vars(ip)
       eth.data.udp.sport=53215

    pcap2.writepkt(eth, ts)

f_in.close()
f_out.close()

print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter
