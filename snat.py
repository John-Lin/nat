# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import struct
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib import addrconv

IDLE_TIME = 100
ARP_TABLE = {}
ports = []


class SNAT(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SNAT, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.nat_intranet_gateway = '192.168.9.1'
        self.nat_ip = '140.92.62.235'
        self.mask = ".".join(self.nat_ip.split('.')[0:3])
        self.nat_extranet_gateway = '140.92.62.1'
        self.fake_mac_eth1 = '00:0e:c6:87:a6:fb'
        self.fake_mac_eth2 = '00:0e:c6:87:a6:fa'
        self.LAN = 3
        self.WAN = 4
        #self.fake_mac_eth1 = '00:10:60:e0:84:ae'
        #self.fake_mac_eth2 = '00:10:60:e0:84:9d'
        # Fake MAC address:
        # eth1 denote intranet
        # eth2 denote extranet
        self.default_port = 2000

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Adding table-miss flow."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, idle_timeout=0, priority=0)
        #self._arp_request(datapath)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Flow-Removed message. When switch send flow-Removed message to controller,
        controller will remove tcp/udp port which is not in use."""
        msg = ev.msg
        #datapath = msg.datapath
        #ofproto = datapath.ofproto

        #if 'tcp_dst' in msg.match:
        try:
            tcp_port = msg.match['tcp_dst']
            udp_port = msg.match['udp_dst']
            #print "Before remove ports", ports
            if tcp_port:
                ports.remove(tcp_port)
            elif udp_port:
                ports.remove(udp_port)
            #print "After remove ports", ports

        #else:
        except:
            pass
         #self.logger.info('OFPFlowRemoved %d', msg.match['tcp_dst'])

    def add_flow(self, datapath, match, actions, idle_timeout, priority):
        """Adding flow entry into flow table."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                idle_timeout=idle_timeout,
                                priority=priority,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def drop_pkt(self, datapath, in_port):
        """Drop the packet."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        actions = []
        self.add_flow(datapath, match, actions, 0, 1)

    def get_port(self):
        """Getting port number sequential increase."""
        port = self.default_port + 1
        self.default_port = port

        if self.default_port > 65535:
            self.default_port = 2000

        if self.default_port not in ports:
            ports.append(self.default_port)
        else:
            port = self.get_port()

        return port

    def get_random_port(self):
        """Getting random port number."""
        port = random.randint(2000, 65535)
        # port = 1024
        if port not in ports:
            ports.append(port)
        else:
            port = self.get_random_port()

        return port
        # When breaking connection need to ports.remove(port)

    def subnet(self, pkt_ip):
        """Checking IP packet's destination ip address.If pkt_ip.dst is on WAN,
        it will assigne the gateway ip address to the target_ip."""
        if pkt_ip:
            if self.mask not in pkt_ip.dst:
                target_ip = self.nat_extranet_gateway
            else:
                target_ip = pkt_ip.dst
        else:
            return

        return target_ip

    def _arp_request(self, datapath, pkt_ip=None):
        """Sending an ARP request via broadcast"""
        # Who has xxx.xxx.xxx.xxx? Tell 140.92.62.235 (NAT's Public IP)
        if pkt_ip is None:
            target_ip = self.nat_extranet_gateway
        else:
            target_ip = self.subnet(pkt_ip)
        print "Sending ARP Request..."
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #target_ip = self.subnet(pkt_ip)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                           dst='ff:ff:ff:ff:ff:ff',
                                           src=self.fake_mac_eth2))

        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                 src_mac=self.fake_mac_eth2,
                                 src_ip=self.nat_ip,
                                 dst_mac='00:00:00:00:00:00',
                                 dst_ip=target_ip))
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def snat(self, datapath, in_port, out_port,
             pkt_ip, pkt_ethernet, pkt_tcp=None, pkt_udp=None, pkt_icmp=None):
        """Source Network Address Translate. Changing IP packet source address
        to NAT's public ip address and add a flow entry."""
        if pkt_tcp is None and pkt_udp is None and pkt_icmp is None:
            return

        parser = datapath.ofproto_parser

        ipv4_src = pkt_ip.src
        ipv4_dst = pkt_ip.dst
        nat_port = self.get_port()

        target_ip = self.subnet(pkt_ip)

        eth_dst = pkt_ethernet.dst
        eth_src = pkt_ethernet.src

        if pkt_tcp is not None:
            #deal with tcp
            #print "TCP"
            tcp_src = pkt_tcp.src_port
            tcp_dst = pkt_tcp.dst_port

            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ip_proto=inet.IPPROTO_TCP,
                                    ipv4_src=ipv4_src,
                                    ipv4_dst=ipv4_dst,
                                    tcp_src=tcp_src,
                                    tcp_dst=tcp_dst)

            actions = [parser.OFPActionSetField(eth_dst=ARP_TABLE[target_ip]),
                       parser.OFPActionSetField(ipv4_src=self.nat_ip),
                       parser.OFPActionSetField(tcp_src=nat_port),
                       parser.OFPActionOutput(out_port)]

            match_reply = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                          ip_proto=inet.IPPROTO_TCP,
                                          ipv4_src=ipv4_dst,
                                          ipv4_dst=self.nat_ip,
                                          tcp_src=tcp_dst,
                                          tcp_dst=nat_port)

            actions_reply = [parser.OFPActionSetField(eth_dst=eth_src),
                             parser.OFPActionSetField(ipv4_dst=ipv4_src),
                             parser.OFPActionSetField(tcp_dst=tcp_src),
                             parser.OFPActionOutput(in_port)]

        elif pkt_udp is not None:
            #deal with udp
            #print "UDP"
            udp_src = pkt_udp.src_port
            udp_dst = pkt_udp.dst_port

            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ip_proto=inet.IPPROTO_UDP,
                                    ipv4_src=ipv4_src,
                                    ipv4_dst=ipv4_dst,
                                    udp_src=udp_src,
                                    udp_dst=udp_dst)

            actions = [parser.OFPActionSetField(eth_dst=ARP_TABLE[target_ip]),
                       parser.OFPActionSetField(ipv4_src=self.nat_ip),
                       parser.OFPActionSetField(udp_src=nat_port),
                       parser.OFPActionOutput(out_port)]

            match_reply = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                          ip_proto=inet.IPPROTO_UDP,
                                          ipv4_src=ipv4_dst,
                                          ipv4_dst=self.nat_ip,
                                          udp_src=udp_dst,
                                          udp_dst=nat_port)

            actions_reply = [parser.OFPActionSetField(eth_dst=eth_src),
                             parser.OFPActionSetField(ipv4_dst=ipv4_src),
                             parser.OFPActionSetField(udp_dst=udp_src),
                             parser.OFPActionOutput(in_port)]

        elif pkt_icmp is not None:
            #deal with icmp
            #print "ICMP"
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ip_proto=inet.IPPROTO_ICMP,
                                    ipv4_src=ipv4_src,
                                    ipv4_dst=ipv4_dst,
                                    icmpv4_type=icmp.ICMP_ECHO_REQUEST)

            actions = [parser.OFPActionSetField(eth_dst=ARP_TABLE[target_ip]),
                       parser.OFPActionSetField(ipv4_src=self.nat_ip),
                       #parser.OFPActionSetField(eth_dst='00:1e:68:a4:74:96'),
                       parser.OFPActionOutput(out_port)]

            match_reply = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                          ip_proto=inet.IPPROTO_ICMP,
                                          #eth_dst=eth_src,
                                          ipv4_src=ipv4_dst,
                                          ipv4_dst=self.nat_ip,
                                          icmpv4_type=icmp.ICMP_ECHO_REPLY)

            actions_reply = [parser.OFPActionSetField(eth_dst=eth_src),
                             parser.OFPActionSetField(ipv4_dst=ipv4_src),
                             parser.OFPActionOutput(in_port)]

        self.add_flow(datapath, match, actions,
                      idle_timeout=IDLE_TIME, priority=10)
        self.add_flow(datapath, match_reply,
                      actions_reply, idle_timeout=IDLE_TIME, priority=10)

        return actions

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        """Handle ARP reply/request packets.
        When controller get an ARP reply packet, it will write into ARP table.
        When controller get an ARP request packet,
        it will reply someone who want to ask NAT's MAC address.
        (Probably under NAT's LAN or WAN)"""
        if pkt_arp.opcode != arp.ARP_REQUEST:
            #it means ARP_REPLY
            if pkt_arp.dst_ip == self.nat_ip:
                # 140.92.62.30 is at xx:xx:xx:xx:xx:xx
                # Got an ARP Reply and parser it.
                #gw_src_mac = pkt_arp.src_mac
                #gw_ip = pkt_arp.src_ip
                ARP_TABLE[pkt_arp.src_ip] = pkt_arp.src_mac
                print "Get ARP reply"
                print ARP_TABLE
            return
        else:
            pass

        # Handle ARP Request and send an ARP Reply
        if pkt_arp.dst_ip == self.nat_intranet_gateway:
            # Who has 192.168.9.1 ?
            # Tell 192.168.9.20(Host), 192.168.9.1's fake MAC address (eth1)
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=pkt_ethernet.src,
                                               src=self.fake_mac_eth1))

            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                     src_mac=self.fake_mac_eth1,
                                     src_ip=self.nat_intranet_gateway,
                                     dst_mac=pkt_arp.src_mac,
                                     dst_ip=pkt_arp.src_ip))
            #print "Send pkt to %s" % pkt_arp.src_mac
            self._send_packet(datapath, port, pkt)
        elif pkt_arp.dst_ip == self.nat_ip:
            # Who has 140.92.62.235 ?
            # Tell 140.92.62.1(Extranet Gateway)
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=pkt_ethernet.src,
                                               src=self.fake_mac_eth2))

            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                     src_mac=self.fake_mac_eth1,
                                     src_ip=self.nat_ip,
                                     dst_mac=pkt_arp.src_mac,
                                     dst_ip=pkt_arp.src_ip))

            self._send_packet(datapath, port, pkt)
        else:
            return

    def _send_packet(self, datapath, port, pkt):
        """Sending packet from controller."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Packet-in message. For packets forwarded to controller,
        that need to be handle."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        try:
            #Some packets format will crash controller (ex:LLDP)
            pkt = packet.Packet(msg.data)
        except:
            return
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        target_ip = self.subnet(pkt_ip)
        port_match = parser.OFPMatch(in_port=in_port)

        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if pkt_ip:
            if target_ip not in ARP_TABLE and port_match['in_port'] == self.LAN:
                # print pkt_ip.src
                self._arp_request(datapath, pkt_ip)
                return

            elif target_ip in ARP_TABLE and port_match['in_port'] == self.LAN:
                if pkt_tcp:
                    #print "There is TCP"
                    actions = self.snat(datapath, in_port, out_port, pkt_ip,
                                        pkt_ethernet, pkt_tcp=pkt_tcp)

                elif pkt_udp:
                    #print "There is UDP"
                    actions = self.snat(datapath, in_port, out_port, pkt_ip,
                                        pkt_ethernet, pkt_udp=pkt_udp)

                elif pkt_icmp:
                    #print "There is ICMP"
                    actions = self.snat(datapath, in_port, out_port, pkt_ip,
                                        pkt_ethernet, pkt_icmp=pkt_icmp)
                else:
                    return
            else:
                return

        elif pkt_arp:
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return

        else:
            return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


def ipv4_text_to_int(ip_text):
    """ ipv4 text to int, return int. """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
