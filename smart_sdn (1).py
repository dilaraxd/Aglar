from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from ryu.topology import event

class SmartSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartSDN, self).__init__(*args, **kwargs)

        # dpid -> datapath
        self.datapaths = {}

        # (src_dpid -> (dst_dpid -> out_port))
        self.adj = {}

        # mac -> (dpid, port)
        self.host_loc = {}

        # port stats: (dpid, port) -> (rx_bytes, tx_bytes)
        self.prev_stats = {}

        # utilization: (dpid, port) -> bytes_per_sec (yaklaşık)
        self.util = {}

        # threshold (bytes/sec) - sonra ayarlarız
        self.CONG_THRESH = 200000  # ~200KB/s

        self.monitor_thread = hub.spawn(self._monitor)

    # ---------- Helpers ----------
    def _traffic_class(self, ip_proto, l4_dst):
        # port-based classification
        if ip_proto == 17 and l4_dst == 53:
            return "DNS"
        if ip_proto == 6 and l4_dst == 80:
            return "HTTP"
        if ip_proto == 6 and l4_dst == 21:
            return "FTP"
        if ip_proto == 6 and l4_dst == 25:
            return "SMTP"
        if ip_proto == 6 and l4_dst == 445:
            return "AD"
        return "OTHER"

    def _add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle, hard_timeout=hard
        )
        datapath.send_msg(mod)

    def _bfs_path(self, src, dst):
        # küçük topo: BFS yeter
        if src == dst:
            return [src]
        q = [src]
        prev = {src: None}
        while q:
            cur = q.pop(0)
            for nxt in self.adj.get(cur, {}):
                if nxt not in prev:
                    prev[nxt] = cur
                    q.append(nxt)
        if dst not in prev:
            return None
        path = []
        x = dst
        while x is not None:
            path.append(x)
            x = prev[x]
        path.reverse()
        return path

    def _path_cost(self, path):
        # yol maliyeti: link util toplamı (yaklaşık)
        cost = 0
        for i in range(len(path)-1):
            a = path[i]
            b = path[i+1]
            outp = self.adj[a][b]
            cost += self.util.get((a, outp), 0)
        return cost

    def _choose_path(self, src_dpid, dst_dpid, is_high_bw=False):
        # Şimdilik: tek path BFS + congestion varsa "alternatif" arayacağız
        # Diamond topo için: iki farklı path çıkarma (basit)
        p1 = self._bfs_path(src_dpid, dst_dpid)
        if not p1:
            return None

        # Alternatif path bulmak için: p1'deki ara linklerden birini geçici "yok say"
        best = p1
        best_cost = self._path_cost(p1)

        if is_high_bw:
            # p1 tıkalıysa alternatif arayalım
            if best_cost > self.CONG_THRESH:
                for i in range(len(p1)-1):
                    a, b = p1[i], p1[i+1]
                    saved = self.adj[a].pop(b, None)
                    try:
                        p2 = self._bfs_path(src_dpid, dst_dpid)
                        if p2:
                            c2 = self._path_cost(p2)
                            if c2 < best_cost:
                                best, best_cost = p2, c2
                    finally:
                        if saved is not None:
                            self.adj.setdefault(a, {})[b] = saved

        return best

    def _install_path_flows(self, path, src_ip, dst_ip, ip_proto, l4_dst, out_to_host_port):
        # path: [s1, s2, s4] gibi
        for i in range(len(path)):
            dpid = path[i]
            dp = self.datapaths.get(dpid)
            if not dp:
                continue
            parser = dp.ofproto_parser

            # next hop port
            if i == len(path)-1:
                out_port = out_to_host_port
            else:
                nxt = path[i+1]
                out_port = self.adj[dpid][nxt]

            actions = [parser.OFPActionOutput(out_port)]

            # QoS: DNS/AD daha yüksek priority
            hi_prio = (ip_proto == 17 and l4_dst == 53) or (ip_proto == 6 and l4_dst == 445)
            prio = 300 if hi_prio else 100

            if ip_proto == 6:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_dst=l4_dst)
            else:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_src=src_ip, ipv4_dst=dst_ip, udp_dst=l4_dst)

            self._add_flow(dp, prio, match, actions, idle=30)

    # ---------- OpenFlow events ----------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        self.adj.setdefault(link.src.dpid, {})[link.dst.dpid] = link.src.port_no

    @set_ev_cls(event.EventLinkDelete)
    def link_del_handler(self, ev):
        link = ev.link
        if link.src.dpid in self.adj and link.dst.dpid in self.adj[link.src.dpid]:
            self.adj[link.src.dpid].pop(link.dst.dpid, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # LLDP ignore
        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst

        # host location learn
        self.host_loc[src] = (dpid, in_port)

        # ARP -> flood
        a = pkt.get_protocol(arp.arp)
        if a:
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            # non-ip -> flood
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        # L4
        l4_dst = None
        if ip.proto == 6:
            t = pkt.get_protocol(tcp.tcp)
            if t:
                l4_dst = t.dst_port
        elif ip.proto == 17:
            u = pkt.get_protocol(udp.udp)
            if u:
                l4_dst = u.dst_port

        if l4_dst is None:
            # ICMP vs -> flood
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        tclass = self._traffic_class(ip.proto, l4_dst)
        if tclass != "OTHER":
            self.logger.info("TRAFFIC %s  %s -> %s  dpid=%s in_port=%s", tclass, ip.src, ip.dst, dpid, in_port)

        # routing (only if we know dst host location)
        if dst not in self.host_loc:
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        src_dpid, _ = self.host_loc[src]
        dst_dpid, dst_port = self.host_loc[dst]

        is_high_bw = (tclass == "FTP")
        path = self._choose_path(src_dpid, dst_dpid, is_high_bw=is_high_bw)
        if not path:
            return

        self._install_path_flows(path, ip.src, ip.dst, ip.proto, l4_dst, dst_port)

        # forward this first packet too
        # next hop from current switch
        if dpid == path[-1]:
            out_port = dst_port
        else:
            idx = path.index(dpid) if dpid in path else 0
            out_port = self.adj[dpid][path[idx+1]]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    # ---------- Monitoring ----------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_port_stats(dp)
            hub.sleep(5)

    def _request_port_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            port_no = stat.port_no
            if port_no > 0xffffff00:  # ignore special ports
                continue

            rx = stat.rx_bytes
            tx = stat.tx_bytes
            key = (dpid, port_no)

            if key in self.prev_stats:
                prev_rx, prev_tx = self.prev_stats[key]
                # 5 sn aralık varsayımı -> bytes/sec yaklaşık
                bps = ((rx - prev_rx) + (tx - prev_tx)) / 5.0
                self.util[key] = max(0, bps)

            self.prev_stats[key] = (rx, tx)
