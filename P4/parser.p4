#include <core.p4>
#include <tna.p4>
#include "headers.p4"

/* Ingress Parser */
parser IngressParser(packet_in pkt,
	out ingress_headers_t hdr,
	out ingress_metadata_t meta,
	out ingress_intrinsic_metadata_t ig_intr_md)
{
	state start {
		pkt.extract(ig_intr_md);
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet_1;
		/*transition select(ig_intr_md.ingress_port) {
			144 : parse_ethernet_1;
			default : parse_ethernet_0;
		}*/
	}

	/*state parse_ethernet_0 {
		pkt.extract(hdr.ethernet);
        transition select((bit<16>)hdr.ethernet.etherType) {
            (bit<16>)ether_type_t.IPV4 : parse_ipv4_0;
            default : accept;
        }
	}

	state parse_ipv4_0{
		pkt.extract(hdr.ipv4);
        transition accept;
	}*/

	state parse_ethernet_1 {
		pkt.extract(hdr.ethernet);
        transition select((bit<16>)hdr.ethernet.etherType) {
            (bit<16>)ether_type_t.IPV4 : parse_ipv4_1;
            default : accept;
        }
	}

	// 解析ip头并收集信息
	state parse_ipv4_1{
		pkt.extract(hdr.ipv4);
		meta.id.ipsrc=hdr.ipv4.srcAddr;
        meta.id.ipdst=hdr.ipv4.dstAddr;
		meta.bwd_id.ipsrc=hdr.ipv4.dstAddr;
        meta.bwd_id.ipdst=hdr.ipv4.srcAddr;
        meta.total_len = hdr.ipv4.total_len;
        transition select(hdr.ipv4.protocol) {
            (bit<8>)ip_proto_t.TCP : parse_tcp;
            (bit<8>)ip_proto_t.UDP : parse_udp;
            default : accept;
        }
	}

	// 解析tcp头并收集信息
	state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.id.src_port = hdr.tcp.src_port;
        meta.id.dst_port = hdr.tcp.dst_port;
		meta.bwd_id.src_port = hdr.tcp.dst_port;
        meta.bwd_id.dst_port = hdr.tcp.src_port;
		meta.window = hdr.tcp.window;
        transition accept;
    }

	// 解析udp头并收集信息
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.id.src_port = hdr.udp.src_port;
        meta.id.dst_port = hdr.udp.dst_port;
		meta.bwd_id.src_port = hdr.udp.dst_port;
        meta.bwd_id.dst_port = hdr.udp.src_port;
		meta.window = 0;
        transition accept;
	}

}

/* Ingress Deparser */
control IngressDeparser(packet_out pkt,
	inout ingress_headers_t hdr,
	in ingress_metadata_t meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
	Mirror() mirror;
	apply {
		if (ig_dprsr_md.mirror_type == 1) {
			/* 将镜像包转发到输出端口，并进行截断 */
			mirror.emit<mirror_h>(meta.session_id, meta.mirror_hdr);
		}
		pkt.emit(hdr);
	}
}

/* Egress Parser */
parser EgressParser(packet_in pkt,
	out egress_headers_t hdr,
	out egress_metadata_t meta,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start {
		pkt.extract(eg_intr_md);
		//pkt.advance(PORT_METADATA_SIZE);
		transition parse_mirror;
	}

	// 提取辅助信息头部
	state parse_mirror {
		pkt.extract(hdr.info);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		//transition parse_ipv4;
		/* 
		 * 最低位0对应0和2的type，为正常流或不必处理
		 * 1对应1和3，分别是异常流的原像和镜像
		 */	
		transition select(hdr.info.type[0:0]) {
			0: parse_ipv4_0;
			1: parse_ipv4_1;
		}
	}

	/* 正常流解析ip头 */
	state parse_ipv4_0 {
		pkt.extract(hdr.oldipv4);
		transition select(hdr.oldipv4.protocol) {
            (bit<8>)ip_proto_t.UDP : parse_udp;
			(bit<8>)ip_proto_t.TCP : parse_tcp;
            default : accept;
        }
	}

	/* 提取正常流的udp包头 */
	state parse_udp {
		pkt.extract(hdr.udp_payload);
		transition select(hdr.udp_payload.dst_port) {
			4791: parse_ib_bth;
			default: accept;
		}
	}

	/* 提取RDMA通讯产生的ACK包的包头 */
	state parse_ib_bth {
		pkt.extract(hdr.ib_bth_msg);
		transition select(hdr.ib_bth_msg.opcode) {
			17: parse_ib_aeth;
			default: accept;
		}
	}
	state parse_ib_aeth {
		pkt.extract(hdr.ib_aeth);
		transition accept;
	}

	// 提取正常流的tcp包头
	state parse_tcp {
		pkt.extract(hdr.tcp_payload);
		transition accept;
	}

	// 提取异常包的包头
	state parse_ipv4_1 {
		pkt.extract(hdr.oldipv4);
		transition parse_subpkg;
	}

	/* 解析子包 */
	state parse_subpkg {
		transition select(hdr.info.subLen[8:0]) {
			//1 0000 0000
			0x100: parse_subpkg_256;
			//0 1000 0000
			0x080: parse_subpkg_128;
			//0 0100 0000
			0x040: parse_subpkg_64;
			//0 0010 0000
			0x020: parse_subpkg_32;
			//0 0001 0000
			0x010: parse_subpkg_16;
			//0 0000 1000
			0x008: parse_subpkg_8;
			//0 0000 0100
			0x004: parse_subpkg_4;
			//0 0000 0010
			0x002: parse_subpkg_2;
			//0 0000 0001
			0x001: parse_subpkg_1;
		}
	}
	state parse_subpkg_256 {
		pkt.extract(hdr.subpkg_256);
		transition accept;
	}
	state parse_subpkg_128 {
		pkt.extract(hdr.subpkg_128);
		transition accept;
	}
	state parse_subpkg_64 {
		pkt.extract(hdr.subpkg_64);
		transition accept;
	}
	state parse_subpkg_32 {
		pkt.extract(hdr.subpkg_32);
		transition accept;
	}
	state parse_subpkg_16 {
		pkt.extract(hdr.subpkg_16);
		transition accept;
	}
	state parse_subpkg_8 {
		pkt.extract(hdr.subpkg_8);
		transition accept;
	}
	state parse_subpkg_4 {
		pkt.extract(hdr.subpkg_4);
		transition accept;
	}
	state parse_subpkg_2 {
		pkt.extract(hdr.subpkg_2);
		transition accept;
	}
	state parse_subpkg_1 {
		pkt.extract(hdr.subpkg_1);
		transition accept;
	}
}

/* Egress Deparser */
control EgressDeparser(packet_out pkt,
	inout egress_headers_t hdr,
	in egress_metadata_t meta,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
	Checksum() ipv4_csum;
	apply {
		if (hdr.newipv4.isValid()) {
			// 计算生成RDMA包的ipv4的checksum
			hdr.newipv4.checksum = ipv4_csum.update({
				hdr.newipv4.version,
				hdr.newipv4.ihl,
				hdr.newipv4.diffserv,
				hdr.newipv4.total_len,
				hdr.newipv4.identification,
				hdr.newipv4.flags,
				hdr.newipv4.fragOffset,
				hdr.newipv4.ttl,
				hdr.newipv4.protocol,
				hdr.newipv4.srcAddr,
				hdr.newipv4.dstAddr
			});
		}
		pkt.emit(hdr);
	}
}