// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 * Types / Constants
 *************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
//const bit<8>  IP_PROTO_PX    = 253;

const ip4Addr_t LEADER_IP = 0x0a000101;   // 10.0.1.1
const bit<16>   ACK_PORT  = 5001;         // UDP dst port for ACKs
const bit<32> EXPECTED_ACKS = 3;
const bit<16> NOTIFY_PORT = 6000;
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
    //ip4Addr_t group_ip;   
    bit<16>   seq;
    //bit<8>    msg_type;   // 0 = REQ, 1 = ACK
    //bit<8>    _pad;
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
    bit<1> notify_leader;
}

/*************************************************************************
 * Parser
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta) {
    state start { transition parse_ethernet; }

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
            17         : parse_udp;  // UDP
            //IP_PROTO_PX: parse_px;   // custom PX (optional)
            default    : accept;
        }
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        
        transition select(hdr.udp.dstPort) {
            ACK_PORT: parse_px;    // ACK vers port 5001 => on attend un header PX
            default:  accept;      // sinon, pas de PX
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

    // 32-bit register with 1 cell to count ACKs
    register<bit<32>>(1) ack_total;
    register<bit<16>>(1) last_seq;
    
//    action inc_ack_total() {
 //       bit<32> v;
   //     ack_total.read(v, 0);
     //   v = v + 1;
       // ack_total.write(0, v);
    //}

    action set_mgid(bit<16> mgid) {
        stdmeta.mcast_grp = mgid;     // multicast replication group
    }

    action set_egress(egressSpec_t port) {
        stdmeta.egress_spec = port;   // unicast output port
    }

    // ARP flood
    table arp_flood {
        key = {
            hdr.ethernet.etherType : exact;
        }
        actions = { set_mgid; NoAction; }
        size = 4;
        default_action = NoAction();
    }

    // IPv4 multicast: dst IP -> mgid
    table ip_mc {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = { set_mgid; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    // Unicast LPM: dst IP -> egress port
    table ack_unicast_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = { set_egress; NoAction; }
        size = 4096;
        default_action = NoAction();  // permissive: do nothing if no rule
    }

    apply {
        // ARP allow flooding
        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == ETHERTYPE_ARP) {
            arp_flood.apply();
        }

        // IPv4 path
        if (hdr.ipv4.isValid()) {
            // Try multicast; if no hit, try unicast
            if (!ip_mc.apply().hit) {
                ack_unicast_lpm.apply();

                // Count UDP ACKs to leader
                if (hdr.udp.isValid() && hdr.px.isValid() &&
                    hdr.ipv4.dstAddr == LEADER_IP &&
                    hdr.udp.dstPort == ACK_PORT) {

		    bit<16> old_seq;

		    bit<32> count;

            	    last_seq.read(old_seq, 0);
            	    ack_total.read(count, 0);

            	    if (hdr.px.seq > old_seq) {
		       // nouveau round
		       old_seq = hdr.px.seq;
		       count   = 0;              
		    }
		    if (hdr.px.seq == old_seq) {
		      // même round
		       count = count + 1;
		    } 
		   
		    last_seq.write(0, old_seq);
    		    ack_total.write(0, count);

    		    // Seuil atteint → marquer pour le leader
       	  	    if (count == EXPECTED_ACKS) {
              	 	meta.notify_leader = 1;
			hdr.udp.dstPort = NOTIFY_PORT;

			//count = 0;
			//ack_total.write(0, count);
    		    }
                }
            }
        }

        // Reflection
        if (stdmeta.mcast_grp == 0 && stdmeta.egress_spec == 0) {
            stdmeta.egress_spec = stdmeta.ingress_port;
        }
    }
}

/*************************************************************************
 * Egress 
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta) {
    apply { }
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
