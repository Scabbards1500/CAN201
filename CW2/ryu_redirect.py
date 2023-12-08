from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, tcp, ipv4


class forwardSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(forwardSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.SERVER1 = {'mac': '00:00:00:00:00:01', 'ip': '10.0.1.2'}
        self.SERVER2 = {'mac': '00:00:00:00:00:02', 'ip': '10.0.1.3'}
        self.CLIENT = {'mac': '00:00:00:00:00:03', 'ip': '10.0.1.5'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            if idle_timeout:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match, idle_timeout=idle_timeout,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        instructions=inst)
        else:
            if idle_timeout:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, idle_timeout=idle_timeout,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if ether_types.ETH_TYPE_ARP == eth.ethertype or ether_types.ETH_TYPE_IP == eth.ethertype:
            self.logger.info("packet1 in dpid=%s src=%s dst=%s in_port=%s", dpid, src, dst, in_port)

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                protocol = ipv4_pkt.proto
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst, ip_proto=protocol)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, 5, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions, 5)
                elif protocol == in_proto.IPPROTO_TCP:
                    if self.SERVER2['mac'] in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][self.SERVER2['mac']]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst)
                    if ipv4_pkt.dst == self.SERVER1['ip'] and ipv4_pkt.src == self.CLIENT['ip']:
                        actions = [parser.OFPActionSetField(eth_dst=self.SERVER2['mac']),
                                   parser.OFPActionSetField(ipv4_dst=self.SERVER2['ip']),
                                   parser.OFPActionOutput(out_port)]
                    elif ipv4_pkt.dst == self.CLIENT['ip'] and ipv4_pkt.src == self.SERVER2['ip']:
                        if self.CLIENT['mac'] in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][self.CLIENT['mac']]
                        else:
                            out_port = ofproto.OFPP_FLOOD
                        actions = [parser.OFPActionSetField(eth_src=self.SERVER1['mac']),
                                   parser.OFPActionSetField(ipv4_src=self.SERVER1['ip']),
                                   parser.OFPActionOutput(out_port)]
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, 5, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions, 5)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        if ether_types.ETH_TYPE_ARP == eth.ethertype or ether_types.ETH_TYPE_IP == eth.ethertype:
            self.logger.info("packet out dpid=%s input_port=%s actions=%s buffer_id=%s", dpid, in_port, actions,
                             msg.buffer_id)
        datapath.send_msg(out)