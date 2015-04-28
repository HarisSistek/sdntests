from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as packet
from pox.openflow.of_json import *

count = 0
dev_port_ip = {}
known_maps = []

# Remember number of bytes sent:
ip_bytes_sent = {}
ip_packets_sent = {}
ip_bytes_recv = {}
ip_packets_recv = {}

def give_map():
    print "-----------"
    for dev in dev_port_ip:
        print dev, dev_port_ip[dev].items()
    
def add_host(dev,port,ip):
    global dev_port_ip
    global known_maps
    if ip in known_maps:
        return

    if dev_port_ip.get(dev):
        info = dev_port_ip.get(dev)
        info[ip] = port
        info[port] = ip
        dev_port_ip[dev] = info
        known_maps.append(ip) # just map once
        return
        
    info = {}
    info[ip] = port
    info[port] = ip
    dev_port_ip[dev] = info
    known_maps.append(ip) # just map once


def add_port_entry(ip, bsent, brecv, psent, precv):
    global ip_bytes_sent
    global ip_bytes_recv
    global ip_packets_sent
    global ip_packets_recv
    
    ip_bytes_sent[ip] = bsent
    ip_bytes_recv[ip] = brecv
    ip_packets_sent[ip] = psent
    ip_packets_recv[ip] = precv
    

def violation_check(ip_bsent, ip_brecv, ip_psent, ip_precv):
    ip_to_catch = "10.0.0.1"
    lim = 1000 # 1000 bytes
    # just check sent for now
    for ip in ip_bsent:
        if ip_to_catch == ip: #  this is the rule check
            if lim < ip_bsent[ip]: # this the rule check
                print "###############################"
                print ip, "has broken lim:", lim, "with", ip_bsent[ip], "sent"

def handle_port_stats(event):
    stats = event.stats
    #print "------------------------"
    for stat in stats:
        if dev_port_ip.get(event.dpid).get(stat.port_no):# if entry exists
            #print "Dev:", event.dpid
            #print dev_port_ip[event.dpid][stat.port_no],"Port:", stat.port_no
            #print "Sendt:", stat.tx_bytes
            #print "Recv:", stat.rx_bytes
            #print "P-Sendt:", stat.tx_packets
            #print "P_Recv:", stat.rx_packets
            #print "------------------------"
            add_port_entry(dev_port_ip[event.dpid][stat.port_no], stat.tx_bytes, 
                           stat.rx_bytes, stat.tx_packets, stat.rx_packets)
    violation_check(ip_bytes_sent, None, None, None)

def handle_packet_in(event):
    global count
    # map first packet i
    packet = event.parsed
    #------------------------------- THis must in:
    if packet.find("ipv4"):
        ip = packet.payload
        add_host(event.dpid, event.port, ip.srcip)
        give_map()

    count = count + 1
    if count == 5:
        send_requests()
        count  = 0

def send_requests():
    print "Sending request:"
    for con in core.openflow._connections.values():
        con.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        print "Sent stat requests to", con

def launch():
    core.openflow.addListenerByName("PortStatsReceived", handle_port_stats) 
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
    send_requests()
