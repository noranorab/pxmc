// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 * Types / Constants
 *************************************************************************/
#define NPORTS 8

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;

const bit<16> ACK_PORT   = 5001;
const bit<16> REQ_PORT   = 5000;
const bit<16> JOIN_PORT  = 5002;
const bit<16> FLOOD_PORT = 5003;
const bit<16> REPLY_PORT = 5004;
const bit<16> CTRL_PORT  = 5005;

const bit<32> MAX_GROUPS = 256;
const bit<NPORTS> ALL_PORTS = 0xFF; // 11111111

// --- NEW: 8 leader slots per group (leader_tag in px.seq[15:13]) ---
const bit<32> NLEADERS   = 8;              // must be 8 (leader_tag is 3 bits)
const bit<32> MAX_SLOTS  = MAX_GROUPS * NLEADERS;  // 256*8 = 2048
const bit<8> SLOT_SHIFT = 3;              // log2(8)

/*************************************************************************
 * Headers
 *************************************************************************/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header px_t {
    ip4Addr_t group_ip;
    bit<16>   seq;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    px_t       px;
}

struct metadata {
    bit<NPORTS> port_mask;
    bit<9>      ingress_port_copy;
}

/*************************************************************************
 * Parser
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17      : parse_udp; // UDP
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            REQ_PORT   : parse_px;
            ACK_PORT   : parse_px;
            JOIN_PORT  : parse_px;
            FLOOD_PORT : parse_px;
            REPLY_PORT : parse_px;
	    CTRL_PORT  : parse_px;
            default    : accept;
        }
    }

    state parse_px {
        packet.extract(hdr.px);
        transition accept;
    }
}

/*************************************************************************
 * Verify / Compute checksum (no-op here)
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

/*************************************************************************
 * Ingress
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t stdmeta) {

    register<bit<32>>(20) debug_regs;

    // --- CHANGED: registers are per (group_idx, leader_tag) slot ---
    register<bit<NPORTS>>(MAX_SLOTS) group_ports;     // active ports for that leader_tag in that group
    register<ip4Addr_t>(MAX_SLOTS)   leader_ip;
    register<bit<16>>(MAX_SLOTS)     leader_seq;      // exact seq of the last FLOOD for that slot
    register<egressSpec_t>(MAX_SLOTS) leader_port;
    register<bit<32>>(MAX_SLOTS)     ack_cnt;
    register<bit<32>>(16) dbg;
    action set_mgid(bit<16> mgid) {
        stdmeta.mcast_grp = mgid;
    }

    // ARP flood
    table arp_flood {
        key = { hdr.ethernet.etherType : exact; }
        actions = { set_mgid; NoAction; }
        size = 4;
        default_action = NoAction();
    }

    apply {
        // defaults: avoid "sticky" metadata across packets
        stdmeta.mcast_grp = 0;
        meta.port_mask = 0;
        meta.ingress_port_copy = 0;

        // packet counter
        bit<32> pkt_idx;
        debug_regs.read(pkt_idx, 0);
        debug_regs.write(0, pkt_idx + 1);

        // ARP
        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == ETHERTYPE_ARP) {
            arp_flood.apply();
        }
	if (hdr.ipv4.isValid()) {
 	   stdmeta.mcast_grp = 1;
	}

        // Only handle PX packets
        if (hdr.ipv4.isValid() && hdr.udp.isValid() && hdr.px.isValid()) {

            // group index: low 8 bits of group_ip
            bit<32> group_idx = (bit<32>) hdr.px.group_ip[7:0];

            // leader_tag: top 3 bits of seq (must be set by host)
            bit<3> leader_tag = hdr.px.seq[15:13];

            // composite slot index: [ group_idx (8 bits) | leader_tag (3 bits) ]
            bit<32> slot_idx = (group_idx << SLOT_SHIFT) | (bit<32>) leader_tag;

            // read current active ports mask for THIS leader slot
            bit<NPORTS> mask;
            group_ports.read(mask, slot_idx);

            // ingress onehot (ports are assumed 1..8)
            bit<8> in_p8 = (bit<8>) stdmeta.ingress_port;

            // guard: if unexpected port (0 or >8), drop safely
            if (in_p8 == 0 || in_p8 > 8) {
                mark_to_drop(stdmeta);
                return;
            }

            bit<8> sh = in_p8 - 1; // 0..7
            bit<NPORTS> inbit = (bit<NPORTS>)((bit<8>)(8w1 << sh));
            bit<NPORTS> outall = (bit<NPORTS>)(ALL_PORTS & (~inbit));

            // debug (optional)
            debug_regs.write(1, ((bit<32>)group_idx << 16) | ((bit<32>)leader_tag << 8) | (bit<32>)hdr.udp.dstPort[7:0]);
            debug_regs.write(2, (bit<32>)slot_idx);
            debug_regs.write(3, (bit<32>)mask);
            debug_regs.write(4, (bit<32>)outall);

            // =========================================================
            // FLOOD (PERM_REQ): remember leader for THIS (group, leader_tag) slot and flood
            // =========================================================
            if (hdr.udp.dstPort == FLOOD_PORT) {

                // reset active ports only for THIS leader slot
                group_ports.write(slot_idx, (bit<NPORTS>)0);

                // remember leader identity for this slot (used to unicast replies back)
                leader_ip.write(slot_idx, hdr.ipv4.srcAddr);
                leader_seq.write(slot_idx, hdr.px.seq); // exact seq of this flood
                leader_port.write(slot_idx, (egressSpec_t) stdmeta.ingress_port);
                ack_cnt.write(slot_idx, 0);
		// DEBUG: store what we think is the leader_port
		bit<32> dbg_val = (bit<32>) stdmeta.ingress_port;
		dbg.write(0, dbg_val);
                // multicast to everyone except ingress (filtered in egress)
                stdmeta.mcast_grp = 1;
                meta.port_mask = outall;
                meta.ingress_port_copy = stdmeta.ingress_port;
            }

            // =========================================================
            // REPLY (PERM_ACK): mark this ingress port as active for THIS slot and unicast to leader
            // =========================================================
            else if (hdr.udp.dstPort == REPLY_PORT) {
	    
                ip4Addr_t     l_ip;
                egressSpec_t  l_port;
                bit<16>       l_seq;

                leader_ip.read(l_ip, slot_idx);
                leader_port.read(l_port, slot_idx);
                leader_seq.read(l_seq, slot_idx);
		dbg.write(1, (bit<32>) l_port);
		dbg.write(2, (bit<32>) stdmeta.ingress_port);
                // robust anti-mismatch: must match BOTH dstAddr and seq of last flood for this slot
                if (hdr.ipv4.dstAddr == l_ip && hdr.px.seq == l_seq) {
              
                    // mark port active for this leader slot
                    bit<NPORTS> cur;
                    group_ports.read(cur, slot_idx);
                    group_ports.write(slot_idx, cur | inbit);

                    // unicast to leader port
                    stdmeta.mcast_grp = 0;
		    dbg.write(3, (bit<32>) l_port);
		    stdmeta.egress_spec = l_port;
                }
		//stdmeta.egress_spec = stdmeta.ingress_port;
            }

            // =========================================================
            // REQ: multicast ONLY to active ports for THIS leader slot
            // =========================================================
            else if (hdr.udp.dstPort == REQ_PORT) {
                stdmeta.mcast_grp = 1;
                meta.port_mask = mask;
                meta.ingress_port_copy = stdmeta.ingress_port;

	    }else if (hdr.udp.dstPort == CTRL_PORT) {
                bit<8> dst_host = (bit<8>) hdr.ipv4.dstAddr[7:0]; // assumes 10.0.1.x -> port x
                if (dst_host >= 1 && dst_host <= 8) {
                    stdmeta.mcast_grp = 0;
                    stdmeta.egress_spec = (egressSpec_t) dst_host;
                } else {
                    mark_to_drop(stdmeta);
                }
            }

            // =========================================================
            // ACK_PORT (optional): forward ACKs to correct leader slot if they match (leader,seq)
            // =========================================================
            else if (hdr.udp.dstPort == ACK_PORT) {

                ip4Addr_t     cur_leader;
                bit<16>       cur_seq;
                bit<32>       cur_cnt;
                egressSpec_t  cur_port;

                leader_ip.read(cur_leader, slot_idx);
                leader_seq.read(cur_seq, slot_idx);
                leader_port.read(cur_port, slot_idx);
                ack_cnt.read(cur_cnt, slot_idx);

                if (hdr.ipv4.dstAddr == cur_leader && hdr.px.seq == cur_seq) {
                    cur_cnt = cur_cnt + 1;
                    ack_cnt.write(slot_idx, cur_cnt);

                    stdmeta.mcast_grp = 0;
                    stdmeta.egress_spec = cur_port;
                } else {
                    mark_to_drop(stdmeta);
                }
            }

            // Other PX traffic: do nothing (unicast forwarding not implemented here)
        }
    }
}

/*************************************************************************
 * Egress
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta) {
    apply {
        // Only filter multicast replications
        if (stdmeta.mcast_grp == 1) {

            bit<8> egr8 = (bit<8>) stdmeta.egress_port;

            // guard: only ports 1..8 are valid in our mask
            if (egr8 == 0 || egr8 > 8) {
                mark_to_drop(stdmeta);
                return;
            }

            bit<8> sh = egr8 - 1; // 0..7
            bit<8> ebit = (8w1) << (bit<3>) sh;

            // Drop if not in mask
            if ((meta.port_mask & (bit<NPORTS>)ebit) == 0) {
                mark_to_drop(stdmeta);
            }

            // Drop if back to ingress
            if (stdmeta.egress_port == meta.ingress_port_copy) {
                mark_to_drop(stdmeta);
            }
        }
    }
}

/*************************************************************************
 * Deparser
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.px);
    }
}

/*************************************************************************
 * v1model Pipeline
 *************************************************************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;