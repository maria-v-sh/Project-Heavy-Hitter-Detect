/*
 * Technion - Israel Institute of Technology
 *
 * Heavy-Hitter Detection on SmatNIC Project
 * Team: Yevhenii Liubchyk, Maria Shestakova
 * Instructors: Itzik Ashkenazi, Prof. Ori Rotenstreich
 */

#define ETHERTYPE_IPV4 0x0800
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

//==========================================================================================================
//Header
//==========================================================================================================
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;
//==========================================================================================================
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}
header ipv4_t ipv4;
//==========================================================================================================
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
header tcp_t tcp;
//==========================================================================================================
header_type udp_t {
	fields {
		srcPort : 16;
        dstPort : 16;
		udplen : 16;
		udpchk : 16;
	}
}
header udp_t udp;
//==========================================================================================================
//Parser
//==========================================================================================================
parser start {
    return parse_ipv4;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        //No default, so drop it if not ipv4 packet
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        TCP_PROTO : parse_tcp;
        UDP_PROTO : parse_udp;
        //No default, so drop it if not tcp or udp
    }
}

parser parse_tcp {
	extract(tcp);
	return ingress; 
}

parser parse_udp {
	extract(udp);
	return ingress; 
}

//==========================================================================================================
//Ingress
//==========================================================================================================
primitive_action hashpipe_algorithm();
action do_forward(port) {
	hashpipe_algorithm();
    modify_field(standard_metadata.egress_spec, port);
}

action do_drop()
{
	drop();
}

@pragma netro no_lookup_caching do_forward;
table forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
		do_forward;
		do_drop;
    }
}
//==========================================================================================================
control ingress {
	apply(forward);
}

//==========================================================================================================
//Egress
//==========================================================================================================
