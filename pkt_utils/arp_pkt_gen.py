from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto.ether import ETH_TYPE_ARP
from ryu.lib.packet import arp
from ryu.ofproto import ether

BROADCAST = 'ff:ff:ff:ff:ff:ff'
TARGET_MAC_ADDRESS = '00:00:00:00:00:00'

def arp_reply(src_mac, src_ip, target_mac, target_ip):
    # Creat an empty Packet instance
    pkt = packet.Packet()

    pkt.add_protocol(ethernet.ethernet(ethertype=ETH_TYPE_ARP,
                                       dst=target_mac,
                                       src=src_mac))

    pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                             src_mac=src_mac,
                             src_ip=src_ip,
                             dst_mac=target_mac,
                             dst_ip=target_ip))

    # Packet serializing
    pkt.serialize()
    data = pkt.data
    # print 'Built up a arp reply packet:', data
    return data

def broadcast_arp_request(src_mac, src_ip, target_ip):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=ETH_TYPE_ARP,
                                       dst=BROADCAST,
                                       src=src_mac))

    pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                             src_mac=src_mac,
                             src_ip=src_ip,
                             dst_mac=TARGET_MAC_ADDRESS,
                             dst_ip=target_ip))
    pkt.serialize()
    data = pkt.data
    # print 'Built up a broadcast arp request packet:', data
    return data

if __name__ == '__main__':
    print arp_reply()
