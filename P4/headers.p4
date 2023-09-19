#include<core.p4>
#include<tna.p4>

/*************************************************************************
 ********** C O N S T A N T S , T Y P E S  A N D  H E A D E R S **********
*************************************************************************/

/* 用于哈希函数的两组不同长度的指标 */
#define LEN_0 1<<16
#define HASH_LEN_0 16

#define LEN_1 1<<20
#define HASH_LEN_1 20

// 以太网协议类型
enum bit<16> ether_type_t {
    IPV4    = 0x0800,
    //ARP     = 0x0806
}

// IP协议类型
enum bit<8> ip_proto_t {
    //ICMP    = 1,
    //IGMP    = 2,
    TCP     = 6,
    UDP     = 17
}

/* 以太头 */
header ethernet_h {
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
}

/* IP头 */
header ipv4_h {
	bit<4>  version;
	bit<4>  ihl;
	bit<8>  diffserv;
    bit<16> total_len;
	bit<16> identification;
	bit<3>  flags;
	bit<13> fragOffset;
	bit<8>  ttl;
    bit<8>  protocol;
	bit<16> checksum;
	bit<32> srcAddr;
	bit<32> dstAddr;
}

/* TCP头 */
header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

/* UDP头 */
header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

/* 用于记录sketch信息 */
header sketch_h {
	bit<16> Bwd_Packet_Length_Min;	// 反向流的最小包长
	bit<16> Bwd_Header_Length;		// 反向流的累积头长度
	bit<16> Max_Packet_Length;		// 正向流的最大包长
	bit<16> Bwd_Packet_Length_Max;	// 反向流的最大包长
	bit<16> Init_Win_bytes_backward;// 反向流的初始窗口大小
    bit<32> Packet_Count;			// 包计数
    bit<32> Packet_Size_Sum;		// 包大小计数
	bit<16> min_seg_size_forward;	// 正向流的最小包头长度
	bit<8> class;					// 类别，0为正常，1为异常
}

/* 用于记录流信息 */
struct flow_id_t {
    bit<32> ipsrc;
    bit<32> ipdst;
    bit<16> src_port;
    bit<16> dst_port;
}

/* 16位对 */
struct pair_16 {
	bit<16> left;
	bit<16> right;
}

/* 32位对 */
struct pair_32 {
    bit<32> left;
    bit<32> right;
}

/* 用于处理加法进位的结构 */
struct b32_carry_t {
	bit<32> oldVal;	// 记录执行加法前低32位值
	bit<32> newVal;	// 记录执行加法后低32位值
}


/* 用于处理子包拆分的额外辅助头 */
header extra_info_h {
	bit<15> type;
	/* 0为不需要额外处理的 
	 * 1为异常流原像
	 * 2为需要保留包头的正常流
	 * 3为异常流的镜像
	 * 4为正常流的包头
	 */
	bit<1> idx;		// 标识RDMA写入的MR编号
	bit<16> subLen;	// 用于异常流记录子包长度
}
/* 镜像包头，同上 */
header mirror_h {
	bit<15>	type;
	bit<1>	idx;
	bit<16>	subLen;
}

/* ib_bth头 */
header ib_bth_h {
    bit<8>  opcode;
    bit<1>  event;
    bit<1>  migReq;
    bit<2>  padCount;
    bit<4>  version;
    bit<16> pkey;
    bit<8>  resv8a;
    bit<24> dstQP;
    bit<1>  ackReq;
    bit<7>  resv7b;
    bit<24> psn;
}

/* ib_reth头，用于RDMA Write */
header ib_reth_h {
    bit<64> va;
    bit<32> rkey;
    bit<32> length;
}

/* ib_aeth头，用于处理RDMA的ACK和NAK */
header ib_aeth_h {
	bit<8> syndrome;
	bit<24> msgSeqNum;
}

/* 从256字节到1字节的子包负载 */
header subpkg_256_h {
	bit<2048> buf;
}
header subpkg_128_h {
	bit<1024> buf;
}
header subpkg_64_h {
	bit<512> buf;
}
header subpkg_32_h {
	bit<256> buf;
}
header subpkg_16_h {
	bit<128> buf;
}
header subpkg_8_h {
	bit<64> buf;
}
header subpkg_4_h {
	bit<32> buf;
}
header subpkg_2_h {
	bit<16> buf;
}
header subpkg_1_h {
	bit<8> buf;
}

/* 用于2字节和1字节子包的4字节对齐填充 */
header padding_2_h {
	bit<16> buf;
}
header padding_1_h {
	bit<24> buf;
}

/* 用于填充CRC */
header CRC_h {
	bit<32> val;
}

/***********************  I N G R E S S  H E A D E R S  ************************/

struct ingress_headers_t {
	extra_info_h info;		// 辅助头部信息

	ethernet_h ethernet;
	ipv4_h     ipv4;
	tcp_h      tcp;
    udp_h      udp;

	sketch_h sketch;		// 记录Sketch信息
}

struct ingress_metadata_t {
	bit<16>   tmp;			// 临时变量
	bit<16>   header_len;	// 记录头长
	bit<16>   total_len;	// 记录总长
	flow_id_t id;			// 流id
	flow_id_t bwd_id;		// 反向流id
	bit<32>   sub;			// 差值
	bit<16>   window;		// 窗口大小
	bit<16>   ip_header_len;// ip头长度

	MirrorId_t session_id;	// 使用的镜像ID
	mirror_h mirror_hdr;	// 镜像辅助头部信息
	
	bit<32> tmp0;	// 临时变量0
	bit<32> tmp1;	// 临时变量1
}


/***********************  E G R E S S  H E A D E R S  ************************/

struct egress_headers_t {
	extra_info_h 	info;   	// 辅助头部信息

	ethernet_h 		ethernet;
	ipv4_h 			newipv4;	// 用于RoCE v2的ipv4头
	udp_h 			udp;		// 用于RoCE v2的udp头
	ib_bth_h   		ib_bth;		// ib_bth头
    ib_reth_h  		ib_reth;	// ib_reth头

	ipv4_h 			oldipv4;	// 记录被拆分子包的ipv4信息头
	
	tcp_h			tcp_payload;	// 用于记录正常流的tcp包头
	udp_h			udp_payload;	// 用于记录正常流的udp包头，以及ACK包的udp部分
	ib_bth_h   		ib_bth_msg;	// 用于监控RDMA双端行为
	ib_aeth_h		ib_aeth;	// ib_aeth头

	subpkg_256_h 	subpkg_256;	// 子包负载
	subpkg_128_h 	subpkg_128;
	subpkg_64_h 	subpkg_64;
	subpkg_32_h 	subpkg_32;
	subpkg_16_h 	subpkg_16;
	subpkg_8_h 		subpkg_8;
	subpkg_4_h 		subpkg_4;
	subpkg_2_h 		subpkg_2;
	padding_2_h		padding_2;	// 用于2字节子包4字节对齐
	subpkg_1_h 		subpkg_1;
	padding_1_h		padding_1;	// 用于1字节子包4字节对齐

	CRC_h 			ib_icrc;	// 用于RDMA的ICRC填充
	CRC_h 			eth_crc;	// 用于Ethernet的CRC填充
}

struct egress_metadata_t {
	bit<32> tmp0;	// 临时变量0
	bit<32> tmp1;	// 临时变量1
	bit<32> tmp2;	// 临时变量2
	bit<32> tmp3;	// 临时变量3
}