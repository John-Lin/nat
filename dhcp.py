"""
 Simple DHCP Server
"""

from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.lib.packet import dhcp, udp, ipv4, ethernet
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib import addrconv

from helper import ofp_helper
from models import settings


class SimpleDHCPServer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDHCPServer, self).__init__(*args, **kwargs)

        self.dhcp_msg_type_code = {
            1: 'DHCP_DISCOVER',
            2: 'DHCP_OFFER',
            3: 'DHCP_REQUEST',
            4: 'DHCP_DECLINE',
            5: 'DHCP_ACK',
            6: 'DHCP_NAK',
            7: 'DHCP_RELEASE',
            8: 'DHCP_INFORM',
        }

        dhcp_settings = settings.load()

        self.dhcp_addr = dhcp_settings['dhcp_gw_addr']

        self.gw_addr = dhcp_settings['dhcp_gw_addr']
        self.broadcast_addr = dhcp_settings['broadcast_addr']

        self.ip_network = dhcp_settings['ip_network']
        self.ip_pool_list = list(self.ip_network)

        self.dns_addr = dhcp_settings['dns_addr']

        self.dhcp_hw_addr = dhcp_settings['dhcp_hw_addr']

        self.mac_to_client_ip = {}

        assert self.dhcp_addr in self.ip_pool_list
        assert self.gw_addr in self.ip_pool_list

        # self.ip_pool_list.remove(self.dhcp_addr)
        self.ip_pool_list.remove(self.gw_addr)
        self.ip_pool_list.remove(self.broadcast_addr)
        self.ip_pool_list.remove(self.ip_network[0])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        dhcpPacket = pkt.get_protocol(dhcp.dhcp)

        if not dhcpPacket:
            return

        if dhcpPacket:
            msgType = ord(dhcpPacket.options.option_list[0].value)
            try:
                self.logger.info("Receive DHCP message type %s" %
                                 (self.dhcp_msg_type_code[msgType]))
            except KeyError:
                self.logger.info("Receive UNKNOWN DHCP message type %d" %
                                 (msgType))

            if msgType == dhcp.DHCP_DISCOVER:
                self.handle_dhcp_discover(dhcpPacket, datapath, in_port)
            elif msgType == dhcp.DHCP_REQUEST:
                self.handle_dhcp_request(dhcpPacket, datapath, in_port)
                self.logger.info(self.mac_to_client_ip)
            else:
                pass

    def handle_dhcp_discover(self, dhcp_pkt, datapath, port):
        try:
            # Choose a IP form IP pool list
            client_ip_addr = str(self.ip_pool_list.pop())
            self.mac_to_client_ip[dhcp_pkt.chaddr] = client_ip_addr
        except IndexError:
            self.logger.info("EMPTY IP POOL")
            return

        # send dhcp_offer message.
        dhcp_offer_msg_type = '\x02'
        self.logger.info("Send DHCP message type %s" %
                         (self.dhcp_msg_type_code[ord(dhcp_offer_msg_type)]))

        msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                 value=dhcp_offer_msg_type)
        options = dhcp.options(option_list=[msg_option])
        hlen = len(addrconv.mac.text_to_bin(dhcp_pkt.chaddr))

        dhcp_pkt = dhcp.dhcp(hlen=hlen,
                             op=dhcp.DHCP_BOOT_REPLY,
                             chaddr=dhcp_pkt.chaddr,
                             yiaddr=client_ip_addr,
                             giaddr=dhcp_pkt.giaddr,
                             xid=dhcp_pkt.xid,
                             options=options)

        self._send_dhcp_packet(datapath, dhcp_pkt, port)

    def handle_dhcp_request(self, dhcp_pkt, datapath, port):
        # send dhcp_ack message.
        dhcp_ack_msg_type = '\x05'
        self.logger.info("Send DHCP message type %s" %
                         (self.dhcp_msg_type_code[ord(dhcp_ack_msg_type)]))

        subnet_option = dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                                    value=addrconv.ipv4.text_to_bin(self.ip_network.netmask))
        gw_option = dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                                value=addrconv.ipv4.text_to_bin(self.gw_addr))
        dns_option = dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                                 value=addrconv.ipv4.text_to_bin(self.dns_addr))
        time_option = dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                                  value='\xFF\xFF\xFF\xFF')
        msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                 value=dhcp_ack_msg_type)
        id_option = dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                                value=addrconv.ipv4.text_to_bin(self.dhcp_addr))

        options = dhcp.options(option_list=[msg_option, id_option,
                               time_option, subnet_option,
                               gw_option, dns_option])
        hlen = len(addrconv.mac.text_to_bin(dhcp_pkt.chaddr))

        # Look up IP by using client mac address
        client_ip_addr = self.mac_to_client_ip[dhcp_pkt.chaddr]

        dhcp_pkt = dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                             hlen=hlen,
                             chaddr=dhcp_pkt.chaddr,
                             yiaddr=client_ip_addr,
                             giaddr=dhcp_pkt.giaddr,
                             xid=dhcp_pkt.xid,
                             options=options)

        self._send_dhcp_packet(datapath, dhcp_pkt, port)

    def _send_dhcp_packet(self, datapath, dhcp_pkt, port):

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet
                         (src=self.dhcp_hw_addr, dst="ff:ff:ff:ff:ff:ff"))
        pkt.add_protocol(ipv4.ipv4
                         (src=self.dhcp_addr, dst="255.255.255.255", proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(dhcp_pkt)

        ofp_helper.send_packet(datapath, pkt, port)
