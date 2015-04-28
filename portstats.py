from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as packet

count = 0
from pox.openflow.of_json import *

dev_port_ip = {}
known_maps = []

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

def handle_flow_stats(event):
    print "Flow stat devID:", event.dpid
    for stat in event.stats:
        match = stat.match
        print ("Flow:",  match.nw_src, ">", match.nw_dst, "prot", match.nw_proto, "byte:", 
               stat.byte_count, "packet:", stat.packet_count, "in port", match.in_port)

def handle_port_stats(event):
    print "########################"
    #print "Port stat devID:", event.dpid
    '''dir(event)
    for stat in event.stats:
        print "###############"
        dir(stat)
    stats = flow_stats_to_list(event.stats)
    print "Pretty"
    for stat in stats:
        print stat'''

def handle_packet_in(event):
    global count
    # map first packet i
    packet = event.parsed
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
        con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
        con.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        print "Sent stat requests to", con

def launch():
    core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats) 
    core.openflow.addListenerByName("PortStatsReceived", handle_port_stats) 
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
    send_requests()
