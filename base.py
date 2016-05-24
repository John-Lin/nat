from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.ofproto import ether
from ryu.ofproto import inet


class Base(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Base, self).__init__(*args, **kwargs)

    def send_get_config_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPGetConfigRequest(datapath)
        datapath.send_msg(req)

    def send_set_config(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 1518)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        flags = []

        if msg.flags & ofp.OFPC_FRAG_NORMAL:
            flags.append('NORMAL')
        if msg.flags & ofp.OFPC_FRAG_DROP:
            flags.append('DROP')
        if msg.flags & ofp.OFPC_FRAG_REASM:
            flags.append('REASM')
        self.logger.debug('OFPGetConfigReply received: '
                          'flags=%s miss_send_len=%d',
                          ','.join(flags), msg.miss_send_len)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ofproto.OFPCML_NO_BUFFER == 65535 (0xFFFF)

        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # set miss_send_length to 1518
        self.send_set_config(datapath)

        # get switch config message
        self.send_get_config_request(datapath)

        # install table-miss flow entry
        self.add_flow(datapath, 0, match, actions)

        # install DHCP request packets flow entry
        match_dhcp_request = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                             ip_proto=inet.IPPROTO_UDP,
                                             udp_src=68, udp_dst=67)
        self.add_flow(datapath, 100, match_dhcp_request, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # (i.e. Please make sure that you should
        # call self.send_set_config(datapath) in switch_features_handler)
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
