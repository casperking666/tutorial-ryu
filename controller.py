# -*- coding: utf-8 -*-

"""
Ryu Tutorial Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. So switch is acting as a hub, controller is not the hub.
Using the tutorial you should convert this to a layer 2 learning switch.

See the README for more...
"""

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import ethernet


class Controller(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_addr = {}

    # I would say kinda ignore this, its like a default
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("Handshake taken place with {}".format(dpid_to_str(datapath.id)))
        self.__add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Packet In Event Handler

        Takes packets provided by the OpenFlow packet in event structure and
        floods them to all ports. This is the core functionality of the Ethernet
        Hub.
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        # standard approach for getting the ethernet stuffs, no error handling
        # solution does have one where they talked about if it's none
        # ethernet is really confusing, so src and dst are both mac addr in_port is port
        eth_header = packet.Packet(data).get_protocol(ethernet.ethernet)
        if eth_header.src not in self.mac_addr:
            self.mac_addr[eth_header.src] = in_port

        dst_mac = eth_header.dst
        if dst_mac in self.mac_addr:
            action = [datapath.ofproto_parser.OFPActionOutput(self.mac_addr[dst_mac])]
            match = parser.OFPMatch(eth_dst=dst_mac)
            # one quite interesting thing for flow table is that, I think its a handshake (well maybe handshaking multiple times...)
            # so even if I only sent one packet from h2 to h4, two flow entries will be created
            # and those two hosts are able to ping each other
            self.__add_flow(datapath, 1, match, action)
        else:
            action = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=action, data=data)
        self.logger.info(f"Sending packet out {dst_mac}")
        datapath.send_msg(out)
        return

    def __add_flow(self, datapath, priority, match, actions):
        '''
        Install Flow Table Modification

        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        self.logger.info("Flow-Mod written to {}".format(dpid_to_str(datapath.id)))
        datapath.send_msg(mod)
