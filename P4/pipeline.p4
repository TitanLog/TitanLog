#include <core.p4>
#include <tna.p4>
#include "headers.p4"
#include "parser.p4"

/* Ingress Pipeline */
control Ingress(inout ingress_headers_t hdr,
		inout ingress_metadata_t meta,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	/* sketch */
	/* 使用两组32位的哈希函数，依靠截取不同区间，获得之后的多组哈希 */
    CRCPolynomial<bit<32>>(coeff=0x04C11DB7,reversed=false, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc32_1;
    CRCPolynomial<bit<32>>(coeff=0x741B8CD7,reversed=false, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc32_2;
    /*CRCPolynomial<bit<32>>(coeff=0xDB710641,reversed=false, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc32_3;
    CRCPolynomial<bit<32>>(coeff=0x82608EDB,reversed=false, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc32_4;*/
    
	/* 正向与反向流的两组id */
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_1) h1;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_1) bwd_h1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_2) h2;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_2) bwd_h2;
    /*Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_3) h3;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_3) bwd_h3;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_4) h4;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32_4) bwd_h4;*/

	// 用于提取一些变量的函数
	Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_same;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_same1;

	// 各组Sketch的寄存器，统一用cm命名方便写的时候查找，实际上并不都是CM
	/*cm1: Bwd_Packet_Length_Min; cm2: Max_Packet_Length; 
	cm3: Bwd_Header_Length; cm4: Bwd_Packet_Length_Max; 
	cm5: Init_win_bytes_backward; cm6: Packet_Count; 
	cm7: Packet_size_sum; cm8: min_seg_size_forward*/
	Register<pair_16,bit<HASH_LEN_0>>(size = LEN_0, initial_value = {0x7fff, 0x7fff}) cm1_1;
    Register<pair_16,bit<HASH_LEN_0>>(size = LEN_0, initial_value = {0x7fff, 0x7fff}) cm1_2;

	Register<bit<16>,bit<HASH_LEN_0>>(LEN_0) cm2_1;
    Register<bit<16>,bit<HASH_LEN_0>>(LEN_0) cm2_2;

	Register<pair_16,bit<HASH_LEN_0>>(LEN_0) cm3_1;
    Register<pair_16,bit<HASH_LEN_0>>(LEN_0) cm3_2;

	Register<pair_16,bit<HASH_LEN_0>>(LEN_0) cm4_1;
    Register<pair_16,bit<HASH_LEN_0>>(LEN_0) cm4_2;

	Register<bit<1>,bit<HASH_LEN_1>>(LEN_1) cm5_1;
    Register<bit<1>,bit<HASH_LEN_1>>(LEN_1) cm5_2;
	Register<bit<1>,bit<HASH_LEN_1>>(LEN_1) cm5_3;
	//Register<bit<1>,bit<HASH_LEN_1>>(LEN_1) cm5_4;

	Register<pair_16,bit<HASH_LEN_0>>(LEN_0) hash_map_1;
	//Register<pair_16,bit<HASH_LEN_0>>(LEN_0) hash_map_2;

	Register<bit<32>,bit<HASH_LEN_0>>(LEN_0) cm6_1;
    Register<bit<32>,bit<HASH_LEN_0>>(LEN_0) cm6_2;

	Register<bit<32>,bit<HASH_LEN_0>>(LEN_0) cm7_1;
    Register<bit<32>,bit<HASH_LEN_0>>(LEN_0) cm7_2;

	Register<pair_16,bit<HASH_LEN_0>>(size = LEN_0, initial_value = {0x7fff, 0x7fff}) cm8_1;
    Register<pair_16,bit<HASH_LEN_0>>(size = LEN_0, initial_value = {0x7fff, 0x7fff}) cm8_2;

	// 用于记录id
	bit<32> i1;
    bit<32> i2;
    //bit<32> i3;
	//bit<32> i4;

	// rx_y代表查询cmx_y的返回结果
	bit<16> r1_1;
	bit<16> r1_2;

    bit<16> r2_1;
	bit<16> r2_2;

	bit<16> r3_1;
	bit<16> r3_2;

	bit<16> r4_1;
	bit<16> r4_2;

	bit<1> r5_1;
	bit<1> r5_2;
	bit<1> r5_3;
	bit<1> r5_4;

	bit<32> r6_1;
	bit<32> r6_2;

	bit<32> r7_1;
	bit<32> r7_2;

	bit<16> r8_1;
	bit<16> r8_2;

	// 计算id，共两组正反向
	action sub() {
        meta.sub = meta.id.ipsrc |-| meta.id.ipdst;
    }
	action cal_i1() {
    	i1 = h1.get({meta.id.ipsrc, meta.id.ipdst, meta.id.src_port, meta.id.dst_port});        
    }
	action cal_i2() {
		i2 = h2.get({meta.id.ipsrc, meta.id.ipdst, meta.id.src_port, meta.id.dst_port});   
    }
	/*action cal_i3() {
    	i3 = h3.get({meta.id.ipsrc, meta.id.ipdst, meta.id.src_port, meta.id.dst_port});        
    }
	action cal_i4() {
    	i4 = h4.get({meta.id.ipsrc, meta.id.ipdst, meta.id.src_port, meta.id.dst_port});        
    }*/
	action cal_bwd_i1() {
    	i1 = bwd_h1.get({meta.bwd_id.ipsrc, meta.bwd_id.ipdst, meta.bwd_id.src_port, meta.bwd_id.dst_port});      
    }
	action cal_bwd_i2() {
    	i2 = bwd_h2.get({meta.bwd_id.ipsrc, meta.bwd_id.ipdst, meta.bwd_id.src_port, meta.bwd_id.dst_port});    
    }
	/*action cal_bwd_i3() {
    	i3 = bwd_h3.get({meta.bwd_id.ipsrc, meta.bwd_id.ipdst, meta.bwd_id.src_port, meta.bwd_id.dst_port});        
    }
	action cal_bwd_i4() {
    	i4 = bwd_h4.get({meta.bwd_id.ipsrc, meta.bwd_id.ipdst, meta.bwd_id.src_port, meta.bwd_id.dst_port});        
    }*/

	/* 这一部分是所有sketch的更新和读取
	 * 调用时，如果是使用反向流的变量，使用cm_x_y_l_t读取src>dst的情况，cm_x_y_r_t反之
	 * 如果是正向流的变量，使用cm_x_y_t即可
	 */
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm1_1) cm1_1_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = min(data.left, meta.total_len);
            result = data.right;
        }
    };
	action cm1_1_l_ins() {
		r1_1 = cm1_1_l_reg.execute(i1[15:0]);
	}
	table cm1_1_l_t {
		actions = {cm1_1_l_ins;}
		size = 1;
		default_action = cm1_1_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm1_1) cm1_1_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = min(data.right, meta.total_len);
            result = data.left;
        }
    };
	action cm1_1_r_ins() {
		r1_1 = cm1_1_r_reg.execute(i1[15:0]);
	}
	table cm1_1_r_t {
		actions = {cm1_1_r_ins;}
		size = 1;
		default_action = cm1_1_r_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm1_2) cm1_2_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = min(data.left, meta.total_len);
            result = data.right;
        }
    };
	action cm1_2_l_ins() {
		r1_2 = cm1_2_l_reg.execute(i2[15:0]);
	}
	table cm1_2_l_t {
		actions = {cm1_2_l_ins;}
		size = 1;
		default_action = cm1_2_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm1_2) cm1_2_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = min(data.right, meta.total_len);
            result = data.left;
        }
    };
	action cm1_2_r_ins() {
		r1_2 = cm1_2_r_reg.execute(i2[15:0]);
	}
	table cm1_2_r_t {
		actions = {cm1_2_r_ins;}
		size = 1;
		default_action = cm1_2_r_ins();
	}

	RegisterAction<bit<16>, bit<HASH_LEN_0>, bit<16>>(cm2_1) cm2_1_reg={
        void apply(inout bit<16> data, out bit<16> result) {
            data = max(data, meta.total_len);
            result = data;
        }
    };
	action cm2_1_ins() {
		r2_1 = cm2_1_reg.execute(i1[15:0]);
	}
	table cm2_1_t {
		actions = {cm2_1_ins;}
		size = 1;
		default_action = cm2_1_ins();
	}
	RegisterAction<bit<16>, bit<HASH_LEN_0>, bit<16>>(cm2_2) cm2_2_reg={
        void apply(inout bit<16> data, out bit<16> result) {
            data = max(data, meta.total_len);
            result = data;
        }
    };
	action cm2_2_ins() {
		r2_2 = cm2_2_reg.execute(i2[15:0]);
	}
	table cm2_2_t {
		actions = {cm2_2_ins;}
		size = 1;
		default_action = cm2_2_ins();
	}

	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm3_1) cm3_1_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = data.left |+| meta.header_len;
            result = data.right;
        }
    };
	action cm3_1_l_ins() {
		r3_1 = cm3_1_l_reg.execute(i1[15:0]);
	}
	table cm3_1_l_t {
		actions = {cm3_1_l_ins;}
		size = 1;
		default_action = cm3_1_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm3_1) cm3_1_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = data.right |+| meta.header_len;
            result = data.left;
        }
    };
	action cm3_1_r_ins() {
		r3_1 = cm3_1_r_reg.execute(i1[15:0]);
	}
	table cm3_1_r_t {
		actions = {cm3_1_r_ins;}
		size = 1;
		default_action = cm3_1_r_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm3_2) cm3_2_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = data.left |+| meta.header_len;
            result = data.right;
        }
    };
	action cm3_2_l_ins() {
		r3_2 = cm3_2_l_reg.execute(i2[15:0]);
	}
	table cm3_2_l_t {
		actions = {cm3_2_l_ins;}
		size = 1;
		default_action = cm3_2_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm3_2) cm3_2_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = data.right |+| meta.header_len;
            result = data.left;
        }
    };
	action cm3_2_r_ins() {
		r3_2 = cm3_2_r_reg.execute(i2[15:0]);
	}
	table cm3_2_r_t {
		actions = {cm3_2_r_ins;}
		size = 1;
		default_action = cm3_2_r_ins();
	}
	
	//
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm4_1) cm4_1_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = max(data.left, meta.total_len);
            result = data.right;
        }
    };
	action cm4_1_l_ins() {
		r4_1 = cm4_1_l_reg.execute(i1[15:0]);
	}
	table cm4_1_l_t {
		actions = {cm4_1_l_ins;}
		size = 1;
		default_action = cm4_1_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm4_1) cm4_1_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = max(data.right, meta.total_len);
            result = data.left;
        }
    };
	action cm4_1_r_ins() {
		r4_1 = cm4_1_r_reg.execute(i1[15:0]);
	}
	table cm4_1_r_t {
		actions = {cm4_1_r_ins;}
		size = 1;
		default_action = cm4_1_r_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm4_2) cm4_2_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = max(data.left, meta.total_len);
            result = data.right;
        }
    };
	action cm4_2_l_ins() {
		r4_2 = cm4_2_l_reg.execute(i2[15:0]);
	}
	table cm4_2_l_t {
		actions = {cm4_2_l_ins;}
		size = 1;
		default_action = cm4_2_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm4_2) cm4_2_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = max(data.right, meta.total_len);
            result = data.left;
        }
    };
	action cm4_2_r_ins() {
		r4_2 = cm4_2_r_reg.execute(i2[15:0]);
	}
	table cm4_2_r_t {
		actions = {cm4_2_r_ins;}
		size = 1;
		default_action = cm4_2_r_ins();
	}

	RegisterAction<bit<1>, bit<HASH_LEN_1>, bit<1>>(cm5_1) cm5_1_reg={
        void apply(inout bit<1> data, out bit<1> result) {
            result = data;
			data = 1;
        }
    };
	action cm5_1_ins() {
		r5_1 = cm5_1_reg.execute(i1[19:0]);
	}
	table cm5_1_t {
		actions = {cm5_1_ins;}
		size = 1;
		default_action = cm5_1_ins();
	}
	RegisterAction<bit<1>, bit<HASH_LEN_1>, bit<1>>(cm5_2) cm5_2_reg={
        void apply(inout bit<1> data, out bit<1> result) {
            result = data;
			data = 1;
        }
    };
	action cm5_2_ins() {
		r5_2 = cm5_2_reg.execute(i2[19:0]);
	}
	table cm5_2_t {
		actions = {cm5_2_ins;}
		size = 1;
		default_action = cm5_2_ins();
	}
	RegisterAction<bit<1>, bit<HASH_LEN_1>, bit<1>>(cm5_3) cm5_3_reg={
        void apply(inout bit<1> data, out bit<1> result) {
            result = data;
			data = 1;
        }
    };
	action cm5_3_ins() {
		r5_3 = cm5_3_reg.execute(i1[31:12]);
	}
	table cm5_3_t {
		actions = {cm5_3_ins;}
		size = 1;
		default_action = cm5_3_ins();
	}
	/*RegisterAction<bit<1>, bit<HASH_LEN_1>, bit<1>>(cm5_4) cm5_4_reg={
        void apply(inout bit<1> data, out bit<1> result) {
            result = data;
			data = 1;
        }
    };
	action cm5_4_ins() {
		r5_4 = cm5_4_reg.execute(i2[31:12]);
	}
	table cm5_4_t {
		actions = {cm5_4_ins;}
		size = 1;
		default_action = cm5_4_ins();
	}*/

    // packet count
    RegisterAction<bit<32>, bit<HASH_LEN_0>, bit<32>>(cm6_1) cm6_1_reg={
        void apply(inout bit<32> data, out bit<32> result) {
            data = data + 1;
            result = data;
        }
    };
	action cm6_1_ins() {
		r6_1 = cm6_1_reg.execute(i1[15:0]);
	}
	table cm6_1_t {
		actions = {cm6_1_ins;}
		size = 1;
		default_action = cm6_1_ins();
	}
	RegisterAction<bit<32>, bit<HASH_LEN_0>, bit<32>>(cm6_2) cm6_2_reg={
        void apply(inout bit<32> data, out bit<32> result) {
            data = data + 1;
            result = data;
        }
    };
	action cm6_2_ins() {
		r6_2 = cm6_2_reg.execute(i2[15:0]);
	}
	table cm6_2_t {
		actions = {cm6_2_ins;}
		size = 1;
		default_action = cm6_2_ins();
	}

    // packet size sum
    RegisterAction<bit<32>, bit<HASH_LEN_0>, bit<32>>(cm7_1) cm7_1_reg={
        void apply(inout bit<32> data, out bit<32> result) {
            data = data + (bit<32>)meta.total_len;
            result = data;
        }
    };
	action cm7_1_ins() {
		r7_1 = cm7_1_reg.execute(i1[15:0]);
	}
	table cm7_1_t {
		actions = {cm7_1_ins;}
		size = 1;
		default_action = cm7_1_ins();
	}
	RegisterAction<bit<32>, bit<HASH_LEN_0>, bit<32>>(cm7_2) cm7_2_reg={
        void apply(inout bit<32> data, out bit<32> result) {
            data = data + (bit<32>)meta.total_len;
            result = data;
        }
    };
	action cm7_2_ins() {
		r7_2 = cm7_2_reg.execute(i2[15:0]);
	}
	table cm7_2_t {
		actions = {cm7_2_ins;}
		size = 1;
		default_action = cm7_2_ins();
	}

	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_1) hash_map_1_insert_right=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            data.right = meta.window;
            result = data.left;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_1) hash_map_1_insert_left=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            data.left = meta.window;
            result = data.right;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_1) hash_map_1_get_left=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            result = data.left;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_1) hash_map_1_get_right=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            result = data.right;
        }
    };
	/*RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_2) hash_map_2_insert_right=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            data.right = meta.window;
            result = data.left;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_2) hash_map_2_insert_left=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            data.left = meta.window;
            result = data.right;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_2) hash_map_2_get_left=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            result = data.left;
        }
    };
    RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(hash_map_2) hash_map_2_get_right=
    {
        void apply(inout pair_16 data, out bit<16> result) 
        {
            result = data.right;
        }
    };*/


	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm8_1) cm8_1_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = min(data.left, meta.header_len);
            result = data.left;
        }
    };
	action cm8_1_l_ins() {
		r8_1 = cm8_1_l_reg.execute(i1[15:0]);
	}
	table cm8_1_l_t {
		actions = {cm8_1_l_ins;}
		size = 1;
		default_action = cm8_1_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm8_1) cm8_1_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = min(data.right, meta.header_len);
            result = data.right;
        }
    };
	action cm8_1_r_ins() {
		r8_1 = cm8_1_r_reg.execute(i1[15:0]);
	}
	table cm8_1_r_t {
		actions = {cm8_1_r_ins;}
		size = 1;
		default_action = cm8_1_r_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm8_2) cm8_2_l_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.left = min(data.left, meta.header_len);
            result = data.left;
        }
    };
	action cm8_2_l_ins() {
		r8_2 = cm8_2_l_reg.execute(i2[15:0]);
	}
	table cm8_2_l_t {
		actions = {cm8_2_l_ins;}
		size = 1;
		default_action = cm8_2_l_ins();
	}
	RegisterAction<pair_16, bit<HASH_LEN_0>, bit<16>>(cm8_2) cm8_2_r_reg={
        void apply(inout pair_16 data, out bit<16> result) {
            data.right = min(data.right, meta.header_len);
            result = data.right;
        }
    };
	action cm8_2_r_ins() {
		r8_2 = cm8_2_r_reg.execute(i2[15:0]);
	}
	table cm8_2_r_t {
		actions = {cm8_2_r_ins;}
		size = 1;
		default_action = cm8_2_r_ins();
	}

	// 用于各类Sketch的取最大最小工作，统一用minx_y命名方便编码
	// 最后会把获取到的信息存入相应的变量中，供决策树计算使用
	action min1_1() {
        hdr.sketch.Bwd_Packet_Length_Min = max(r1_1, r1_2);
    }
	table min1_1_t {
        actions = {min1_1;}
		size = 1;
        default_action = min1_1;
    }
	action min2_1() {
        hdr.sketch.Max_Packet_Length = min(r2_1, r2_2);
    }
	table min2_1_t {
        actions = {min2_1;}
		size = 1;
        default_action = min2_1;
    }
	action min3_1() {
        hdr.sketch.Bwd_Header_Length = min(r3_1, r3_2);
    }
	table min3_1_t {
        actions = {min3_1;}
		size = 1;
        default_action = min3_1;
    }
	action min4_1() {
        hdr.sketch.Bwd_Packet_Length_Max = min(r4_1, r4_2);
    }
	table min4_1_t {
        actions = {min4_1;}
		size = 1;
        default_action = min4_1;
    }
    action min6_1() {
        hdr.sketch.Packet_Count = min(r6_1, r6_2);
    }
	table min6_1_t {
        actions = {min6_1;}
		size = 1;
        default_action = min6_1;
    }
    action min7_1() {
        hdr.sketch.Packet_Size_Sum = min(r7_1, r7_2);
    }
	table min7_1_t {
        actions = {min7_1;}
		size = 1;
        default_action = min7_1;
    }
	action min8_1() {
        hdr.sketch.min_seg_size_forward = max(r8_1, r8_2);
    }
	table min8_1_t {
        actions = {min8_1;}
		size = 1;
        default_action = min8_1;
    }

	/* 用于模拟average packet_size的计算单元
	 * 具体做法为根据每组平均值的比较阈值进行一个乘法处理
	 * 计算出packet_count和阈值的近似乘积，再和total_size进行比较
	 */
    // calculate packet_count * threshold
	bit<32> mul01;
	bit<32> mul02;
	bit<32> mul03;
	//bit<32> mul04;
	//bit<32> mul05;
	//bit<32> mul06;
	//bit<32> mul07;
	bit<32> mul08;
	bit<32> mul09;
	bit<32> mul10;
	//bit<32> mul11;

	action mul_count(bit<32> m01, bit<32> m02, bit<32> m03, /*bit<32> m04,
					 bit<32> m05, bit<32> m06, bit<32> m07,*/ bit<32> m08,
					 bit<32> m09, bit<32> m10/*, bit<32> m11*/)
	{
		mul01 = m01;
		mul02 = m02;
		mul03 = m03;
		//mul04 = m04;
		//mul05 = m05;
		//mul06 = m06;
		//mul07 = m07;
		mul08 = m08;
		mul09 = m09;
		mul10 = m10;
		//mul11 = m11;
	}
	action default_mul() {
		mul01 = 0xffffffff;
		mul02 = 0xffffffff;
		mul03 = 0xffffffff;
		mul08 = 0xffffffff;
		mul09 = 0xffffffff;
		mul10 = 0xffffffff;
	}
	// 进行乘法模拟的表，主要在控制面进行计算
	table mul_count_t {
		key = {
			hdr.sketch.Packet_Count: lpm;
		}
		actions = {
			mul_count;
			default_mul;
		}
		size = 16384;
		default_action = default_mul;
	}

	/* decision tree */
	/* 形如dtx的变量表示为第x层决策树的结果
	 * 后缀表示前几层的选择情况，比方01表示第一层向左，第二层向右
	 */
	bit<16> dt1;
	bit<16> dt2_0;
	bit<16> dt3_00;
	bit<16> dt4_000;
	bit<16> dt5_0000;
	bit<16> dt6_00000;
	bit<16> dt6_00001;
	bit<16> dt5_0001;
	bit<16> dt6_00011;
	bit<16> dt4_001;
	bit<32> dt5_0010;
	bit<16> dt6_00100;
	bit<16> dt5_0011;
	bit<16> dt6_00110;
	bit<32> dt6_00111;
	bit<32> dt3_01;
	//bit<16> dt4_010;
	//bit<16> dt5_0100;
	//bit<16> dt5_0101;
	//bit<32> dt6_01010;
	//bit<32> dt6_01011;
	bit<16> dt4_011;
	//bit<16> dt5_0110;
	//bit<32> dt6_01100;
	//bit<32> dt5_0111;
	//bit<16> dt6_01111;
	bit<32> dt2_1;
	bit<16> dt3_10;
	bit<32> dt4_100;
	//bit<16> dt5_1000;
	//bit<16> dt6_10000;
	//bit<16> dt6_10001;
	bit<16> dt5_1001;
	//bit<16> dt6_10010;
	//bit<16> dt4_101;
	//bit<16> dt5_1011;
	bit<16> dt3_11;
	bit<32> dt4_110;
	bit<16> dt5_1100;
	bit<16> dt6_11000;
	//bit<32> dt5_1101;
	//bit<16> dt6_11011;
	bit<16> dt4_111;
	bit<16> dt5_1111;
	
	// 计算决策树节点
	action cal_dt1() {
		dt1 = 3398 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt1_t {
		actions = {cal_dt1;}
		size = 1;
		const default_action = cal_dt1;
	}
	action cal_dt2_0() {
		dt2_0 = 5753 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt2_0_t {
		actions = {cal_dt2_0;}
		size = 1;
		const default_action = cal_dt2_0;
	}
	action cal_dt3_00() {
		dt3_00 = 420 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt3_00_t {
		actions = {cal_dt3_00;}
		size = 1;
		const default_action = cal_dt3_00;
	}
	action cal_dt4_000() {
		dt4_000 = 0 |-| hdr.sketch.Bwd_Packet_Length_Min;
	}
	table cal_dt4_000_t {
		actions = {cal_dt4_000;}
		size = 1;
		const default_action = cal_dt4_000;
	}
	action cal_dt5_0000() {
		dt5_0000 = 18576 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt5_0000_t {
		actions = {cal_dt5_0000;}
		size = 1;
		const default_action = cal_dt5_0000;
	}
	action cal_dt6_00000() {
		dt6_00000 = 136 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt6_00000_t {
		actions = {cal_dt6_00000;}
		size = 1;
		const default_action = cal_dt6_00000;
	}
	action cal_dt6_00001() {
		dt6_00001 = 64887 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt6_00001_t {
		actions = {cal_dt6_00001;}
		size = 1;
		const default_action = cal_dt6_00001;
	}
	action cal_dt5_0001() {
		dt5_0001 = 14 |-| hdr.sketch.min_seg_size_forward;
	}
	table cal_dt5_0001_t {
		actions = {cal_dt5_0001;}
		size = 1;
		const default_action = cal_dt5_0001;
	}
	action cal_dt6_00011() {
		dt6_00011 = 85 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt6_00011_t {
		actions = {cal_dt6_00011;}
		size = 1;
		const default_action = cal_dt6_00011;
	}
	action cal_dt4_001() {
		dt4_001 = 4343 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt4_001_t {
		actions = {cal_dt4_001;}
		size = 1;
		const default_action = cal_dt4_001;
	}
	action cal_dt5_0010() {
		dt5_0010 = mul01 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt5_0010_t {
		actions = {cal_dt5_0010;}
		size = 1;
		const default_action = cal_dt5_0010;
	}
	action cal_dt6_00100() {
		dt6_00100 = 18576 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt6_00100_t {
		actions = {cal_dt6_00100;}
		size = 1;
		const default_action = cal_dt6_00100;
	}
	action cal_dt5_0011() {
		dt5_0011 = 966 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt5_0011_t {
		actions = {cal_dt5_0011;}
		size = 1;
		const default_action = cal_dt5_0011;
	}
	action cal_dt6_00110() {
		dt6_00110 = 4380 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt6_00110_t {
		actions = {cal_dt6_00110;}
		size = 1;
		const default_action = cal_dt6_00110;
	}
	action cal_dt6_00111() {
		dt6_00111 = mul02 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt6_00111_t {
		actions = {cal_dt6_00111;}
		size = 1;
		const default_action = cal_dt6_00111;
	}
	action cal_dt3_01() {
		dt3_01 = mul03 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt3_01_t {
		actions = {cal_dt3_01;}
		size = 1;
		const default_action = cal_dt3_01;
	}
	/*action cal_dt4_010() {
		dt4_010 = 2858 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt4_010_t {
		actions = {cal_dt4_010;}
		size = 1;
		const default_action = cal_dt4_010;
	}*/
	/*action cal_dt5_0100() {
		dt5_0100 = 11656 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt5_0100_t {
		actions = {cal_dt5_0100;}
		size = 1;
		const default_action = cal_dt5_0100;
	}*/
	/*action cal_dt5_0101() {
		dt5_0101 = 512 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt5_0101_t {
		actions = {cal_dt5_0101;}
		size = 1;
		const default_action = cal_dt5_0101;
	}*/
	/*action cal_dt6_01010() {
		dt6_01010 = mul04 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt6_01010_t {
		actions = {cal_dt6_01010;}
		size = 1;
		const default_action = cal_dt6_01010;
	}*/
	/*action cal_dt6_01011() {
		dt6_01011 = mul05 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt6_01011_t {
		actions = {cal_dt6_01011;}
		size = 1;
		const default_action = cal_dt6_01011;
	}*/
	action cal_dt4_011() {
		dt4_011 = 774 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt4_011_t {
		actions = {cal_dt4_011;}
		size = 1;
		const default_action = cal_dt4_011;
	}
	/*action cal_dt5_0110() {
		dt5_0110 = 206 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt5_0110_t {
		actions = {cal_dt5_0110;}
		size = 1;
		const default_action = cal_dt5_0110;
	}*/
	/*action cal_dt6_01100() {
		dt6_01100 = mul06 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt6_01100_t {
		actions = {cal_dt6_01100;}
		size = 1;
		const default_action = cal_dt6_01100;
	}*/
	/*action cal_dt5_0111() {
		dt5_0111 = mul07 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt5_0111_t {
		actions = {cal_dt5_0111;}
		size = 1;
		const default_action = cal_dt5_0111;
	}*/
	/*action cal_dt6_01111() {
		dt6_01111 = 26 |-| hdr.sketch.min_seg_size_forward;
	}
	table cal_dt6_01111_t {
		actions = {cal_dt6_01111;}
		size = 1;
		const default_action = cal_dt6_01111;
	}*/
	action cal_dt2_1() {
		dt2_1 = mul08 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt2_1_t {
		actions = {cal_dt2_1;}
		size = 1;
		const default_action = cal_dt2_1;
	}
	action cal_dt3_10() {
		dt3_10 = 1275 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt3_10_t {
		actions = {cal_dt3_10;}
		size = 1;
		const default_action = cal_dt3_10;
	}
	action cal_dt4_100() {
		dt4_100 = mul09 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt4_100_t {
		actions = {cal_dt4_100;}
		size = 1;
		const default_action = cal_dt4_100;
	}
	/*action cal_dt5_1000() {
		dt5_1000 = 275 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt5_1000_t {
		actions = {cal_dt5_1000;}
		size = 1;
		const default_action = cal_dt5_1000;
	}*/
	/*action cal_dt6_10000() {
		dt6_10000 = 258 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt6_10000_t {
		actions = {cal_dt6_10000;}
		size = 1;
		const default_action = cal_dt6_10000;
	}*/
	/*action cal_dt6_10001() {
		dt6_10001 = 928 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt6_10001_t {
		actions = {cal_dt6_10001;}
		size = 1;
		const default_action = cal_dt6_10001;
	}*/
	action cal_dt5_1001() {
		dt5_1001 = 4608 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt5_1001_t {
		actions = {cal_dt5_1001;}
		size = 1;
		const default_action = cal_dt5_1001;
	}
	/*action cal_dt6_10010() {
		dt6_10010 = 3402 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt6_10010_t {
		actions = {cal_dt6_10010;}
		size = 1;
		const default_action = cal_dt6_10010;
	}*/
	/*action cal_dt4_101() {
		dt4_101 = 8749 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}
	table cal_dt4_101_t {
		actions = {cal_dt4_101;}
		size = 1;
		const default_action = cal_dt4_101;
	}*/
	/*action cal_dt5_1011() {
		dt5_1011 = 14 |-| hdr.sketch.min_seg_size_forward;
	}
	table cal_dt5_1011_t {
		actions = {cal_dt5_1011;}
		size = 1;
		const default_action = cal_dt5_1011;
	}*/
	action cal_dt3_11() {
		dt3_11 = 16718 |-| hdr.sketch.Max_Packet_Length;
	}
	table cal_dt3_11_t {
		actions = {cal_dt3_11;}
		size = 1;
		const default_action = cal_dt3_11;
	}
	action cal_dt4_110() {
		dt4_110 = mul10 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt4_110_t {
		actions = {cal_dt4_110;}
		size = 1;
		const default_action = cal_dt4_110;
	}
	action cal_dt5_1100() {
		dt5_1100 = 3866 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt5_1100_t {
		actions = {cal_dt5_1100;}
		size = 1;
		const default_action = cal_dt5_1100;
	}
	action cal_dt6_11000() {
		dt6_11000 = 29080 |-| hdr.sketch.Init_Win_bytes_backward;
	}
	table cal_dt6_11000_t {
		actions = {cal_dt6_11000;}
		size = 1;
		const default_action = cal_dt6_11000;
	}
	/*action cal_dt5_1101() {
		dt5_1101 = mul11 |-| hdr.sketch.Packet_Size_Sum;
	}
	table cal_dt5_1101_t {
		actions = {cal_dt5_1101;}
		size = 1;
		const default_action = cal_dt5_1101;
	}*/
	/*action cal_dt6_11011() {
		dt6_11011 = 34728 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt6_11011_t {
		actions = {cal_dt6_11011;}
		size = 1;
		const default_action = cal_dt6_11011;
	}*/
	/*action cal_dt4_111() {
		dt4_111 = 34746 |-| hdr.sketch.Bwd_Header_Length;
	}
	table cal_dt4_111_t {
		actions = {cal_dt4_111;}
		size = 1;
		const default_action = cal_dt4_111;
	}*/
	/*action cal_dt5_1111() {
		dt5_1111 = 17853 |-| hdr.sketch.Bwd_Packet_Length_Max;
	}	
	table cal_dt5_1111_t {
		actions = {cal_dt5_1111;}
		size = 1;
		const default_action = cal_dt5_1111;
	}*/


	/* RDMA */
	/* 处理异常包，将原包转发到回环端口，并将镜像包送往发送端口 */
	action send_and_copy() {
		ig_tm_md.ucast_egress_port = 136;
		ig_dprsr_md.mirror_type = 1;

		/* 设置原像包类型 */
		hdr.info.type = 1;
		hdr.info.idx = 0;
		/* 设置镜像包类型 */
		meta.mirror_hdr.setValid();
		meta.mirror_hdr.type = 3;
		meta.mirror_hdr.idx = 0;
	}

	/* 处理常规通信，简单转发原包 */
	action send(PortId_t port, bit<15> type) {
		ig_tm_md.ucast_egress_port = port;
		hdr.info.type = type;
	}

	/* 简单丢弃原包 */
	action drop() {
		hdr.info.type = 0;
		ig_dprsr_md.mirror_type = 0;
		ig_dprsr_md.drop_ctl = 1;
	}

	/* 基于入端口的转发表 */
	table src_port_table {
		key = {
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			send;
			send_and_copy;
			drop;
		}
		size = 8;
		default_action = drop;
	}

	/* 将检测到的异常包发往回环端口 */
	action sendABN() {
		hdr.sketch.class = 1;
		ig_tm_md.ucast_egress_port = 136;
		ig_dprsr_md.mirror_type = 0;

		/* 设置原像包类型 */
		hdr.info.type = 0;
		hdr.info.idx = 0;

		/* 取消丢弃包 */
		ig_dprsr_md.drop_ctl = 0;
	}

	table sendABN_table {
		actions = {
			sendABN;
		}
		size = 1;
		default_action = sendABN;
	}

	/* 将检测到的正常包发往不同的截断包头的回环端口 */
	action sendNRM(MirrorId_t sid) {
		hdr.sketch.class = 0;

		ig_dprsr_md.mirror_type = 1;
		/* 设置镜像会话号 */
		meta.session_id = sid;
		/* 设置镜像包类型 */
		meta.mirror_hdr.setValid();
		meta.mirror_hdr.type = 2;
		meta.mirror_hdr.idx = 0;
	}

	/* 基于totalLen确定当前划分子包长度 */
	action getSublen(bit<16> subLen, MirrorId_t sid) {
		meta.mirror_hdr.subLen = subLen;
		hdr.info.subLen = subLen;
		/* 设置镜像会话号 */
		meta.session_id = sid;
	}

	table sub_table {
		key = {
			hdr.ipv4.total_len: range;
		}
		actions = {
			getSublen;
			drop;
		}
		size = 16;
		default_action = drop;
	}

	/*table drop_table {
		actions = {
			drop;
		}
		size = 1;
		const default_action = drop;
	}*/

	/* 基于子包长度获取偏移量加法计算单元 */
	action initOffset() {
		meta.tmp0[15:0] = hdr.info.subLen + 20;
		meta.tmp0[31:16] = 0;
	}
	table initOffset_table {
		actions = {
			initOffset;
		}
		size = 1;
		const default_action = initOffset;
	}

	/* 计算正常包包头带来的偏移增量 */
	action initOffset_N() {
		hdr.info.subLen = hdr.ipv4.total_len - 20;
		meta.tmp0[15:0] = hdr.ipv4.total_len;
		meta.tmp0[31:16] = 0;
	}
	table initOffset_N_table {
		actions = {
			initOffset_N;
		}
		size = 1;
		const default_action = initOffset_N;
	}

	/* 进位判断加法器
	 * 根据低32位的加法运算前后的对比，判断是否产生进位
	 * 进位返回1，不进位返回0
	 * 用于预测，所以为了避免判断的滞后性，设置初始值为276（最大的子包长度）
	 */
	Register<b32_carry_t, bit<1>>(1) offset_cr_reg;
	RegisterAction<b32_carry_t, bit<1>, bit<32>>(offset_cr_reg) offset_cr_action = {
		void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
				reg.oldVal = 276;
				reg.newVal = 276 + meta.tmp0;
			}
			else {
				reg.oldVal = reg.newVal;
				reg.newVal = reg.newVal + meta.tmp0;
			}
		}
	};
	action offset_cr() {
		meta.tmp0 = offset_cr_action.execute(0);
	}
	table offset_cr_table {
		actions = {
			offset_cr;
		}
		size = 1;
		const default_action = offset_cr;	
	}

	/* 高位判断加法器
	 * 根据高32位的值进行处理，判断当前拆分子包累积大小是否超过某个界限（本代码中为8G）
	 */
	Register<bit<32>, bit<1>>(1) offset_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(offset_hi_reg) offset_hi_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			if (reg + meta.tmp0 == 0x00000002) {
				rst = 1;
				reg = 0;
			}
			else {
				rst = 0;
				reg = reg + meta.tmp0;
			}
        }
    };
	action offset_hi() {
		meta.tmp1 = offset_hi_action.execute(0);
	}
	table offset_hi_table {
		actions = {
			offset_hi;
		}
		size = 1;
		const default_action = offset_hi;
	}

	/* MR编号寄存器
	 * 用于记录当前使用的MR编号，在其中一块用完后，其取值会进行切换
	 */
	Register<bit<32>, bit<1>>(1) mr_reg;
	RegisterAction<bit<32>, bit<1>, bit<1>>(mr_reg) mr_choose_action = {
		void apply(inout bit<32> reg, out bit<1> rst) {
			if (meta.tmp1 == 1) {
				reg = reg^1;
			}
			rst = reg[0:0];
		}
	};
	action chooseMR() {
		meta.mirror_hdr.idx = mr_choose_action.execute(0);
	}
	table chooseMR_table {
		actions = {
			chooseMR;
		}
		size = 1;
		const default_action = chooseMR;
	}

	/* ingress processing*/
	apply {
		hdr.info.setValid();
		hdr.sketch.setValid();

		// 根据入端口判断是初始流量还是等待写入远端的流量
		if (src_port_table.apply().hit) {
			// 这里处理等待写入远端的流量

			/* 简单解析原像包本轮子包带来的偏移量增量 */
			if (hdr.info.type == 1) {
				sub_table.apply(); 	// 计算子包长度
				initOffset_table.apply();	// 设定偏移量加法单元
			}
			else if (hdr.info.type == 4) {
				// 设定正常流的偏移量加法单元
				initOffset_N_table.apply();
			}

			if (ig_dprsr_md.drop_ctl == 0) {
				offset_cr_table.apply();	// 计算进位情况
				offset_hi_table.apply();	// 计算高位情况
				chooseMR_table.apply();		// 查询MR编号
			}
		}
		else if (hdr.udp.isValid() || hdr.tcp.isValid()) {
			// 这里处理udp和tcp的初始流量

			// 计算头部和整体长度信息，并先将包标识为正常流
			meta.ip_header_len = hash_same.get({hdr.ipv4.ihl});
			if (hdr.udp.isValid()) {
				meta.header_len = 2;
				// 保留UDP头部的正常流
				sendNRM(10);
			} else {
				meta.header_len = hash_same1.get({hdr.tcp.data_offset});
				// 保留TCP头部的正常流
				sendNRM(11);
			}
			meta.ip_header_len = meta.ip_header_len << 2;
			meta.header_len = meta.header_len << 2;
			meta.total_len = meta.total_len |-| meta.ip_header_len;
			meta.total_len = meta.total_len |-| meta.header_len;

			// 根据src和dst的大小情况计算id
            sub();
			if (meta.sub != 0) {
				//src > dst
                cal_bwd_i1();
				cal_bwd_i2();
				/*cal_bwd_i3();
				cal_bwd_i4();*/
			} else {
                cal_i1();
				cal_i2();
				/*cal_i3();
				cal_i4();*/
			}
			// 更新和获取各个sketch的信息
			if (meta.sub != 0) {
				//src > dst
                cm1_1_l_t.apply();
				cm1_2_l_t.apply();
			} else {
                cm1_1_r_t.apply();
				cm1_2_r_t.apply();
			}
			cm2_1_t.apply();
			cm2_2_t.apply();
			if (meta.sub != 0) {
				//src > dst
                cm3_1_l_t.apply();
				cm3_2_l_t.apply();
			} else {
                cm3_1_r_t.apply();
				cm3_2_r_t.apply();
			}
			if (meta.sub != 0) {
				//src > dst
				cm4_1_l_t.apply();
				cm4_2_l_t.apply();
			} else {
				cm4_1_r_t.apply();
				cm4_2_r_t.apply();
			}
			cm5_1_t.apply();
			cm5_2_t.apply();
			cm5_3_t.apply();
			//cm5_4_t.apply();

			cm6_1_t.apply();
            cm6_2_t.apply();

			cm7_1_t.apply();
            cm7_2_t.apply();

			if (meta.sub != 0) {
				//src > dst
                cm8_1_l_t.apply();
				cm8_2_l_t.apply();
			} else {
                cm8_1_r_t.apply();
				cm8_2_r_t.apply();
			}

			// 将获取的sketch信息进行进一步处理，获取想要的变量
			min1_1_t.apply();
			min2_1_t.apply();
			min3_1_t.apply();
			min4_1_t.apply();
			// 这里是一个bloom filter结构
			if (r5_1 == 0 || r5_2 == 0 || r5_3 == 0 /*|| r5_4 == 0*/) {    
                if (meta.sub != 0) // meta.flow_id.ipsrc > meta.flow_id.ipdst 升序流就加左边返回右边的值，降序流就加右边返回左边的值
                    hdr.sketch.Init_Win_bytes_backward = hash_map_1_insert_left.execute(i1[31:16]);
                else
                    hdr.sketch.Init_Win_bytes_backward = hash_map_1_insert_right.execute(i1[31:16]);
            } else {
                if (meta.sub != 0) // meta.flow_id.ipsrc > meta.flow_id.ipdst 升序流就加左边返回右边的值，降序流就加右边返回左边的值
                    hdr.sketch.Init_Win_bytes_backward = hash_map_1_get_right.execute(i1[31:16]);
                else
                    hdr.sketch.Init_Win_bytes_backward = hash_map_1_get_left.execute(i1[31:16]);
            }
			min6_1_t.apply();
			min7_1_t.apply();
			min8_1_t.apply();
			
			// 计算packet_count与阈值的乘积
			mul_count_t.apply();

			// 依次计算各决策树节点，注释部分为被裁剪掉的分支
			cal_dt1_t.apply();
			cal_dt2_0_t.apply();
			cal_dt3_00_t.apply();
			cal_dt4_000_t.apply();
			cal_dt5_0000_t.apply();
			cal_dt6_00000_t.apply();
			cal_dt6_00001_t.apply();
			cal_dt5_0001_t.apply();
			cal_dt6_00011_t.apply();
			cal_dt4_001_t.apply();
			cal_dt5_0010_t.apply();
			cal_dt6_00100_t.apply();
			cal_dt5_0011_t.apply();
			cal_dt6_00110_t.apply();
			cal_dt6_00111_t.apply();
			cal_dt3_01_t.apply();
			//cal_dt4_010_t.apply();
			//cal_dt5_0100_t.apply();
			//cal_dt5_0101_t.apply();
			//cal_dt6_01010_t.apply();
			//cal_dt6_01011_t.apply();
			cal_dt4_011_t.apply();
			//cal_dt5_0110_t.apply();
			//cal_dt6_01100_t.apply();
			//cal_dt5_0111_t.apply();
			//cal_dt6_01111_t.apply();
			cal_dt2_1_t.apply();
			cal_dt3_10_t.apply();
			cal_dt4_100_t.apply();
			//cal_dt5_1000_t.apply();
			//cal_dt6_10000_t.apply();
			//cal_dt6_10001_t.apply();
			cal_dt5_1001_t.apply();
			//cal_dt6_10010_t.apply();
			//cal_dt4_101_t.apply();
			//cal_dt5_1011_t.apply();
			cal_dt3_11_t.apply();
			cal_dt4_110_t.apply();
			cal_dt5_1100_t.apply();
			cal_dt6_11000_t.apply();
			//cal_dt5_1101_t.apply();
			//cal_dt6_11011_t.apply();
			//cal_dt4_111_t.apply();
			//cal_dt5_1111_t.apply();

			// 决策树，出现sendABN_table.apply()说明该分支对应异常包
			if (dt1 != 0) {
				if (dt2_0 != 0) {
					if (dt3_00 != 0) {
						if (dt4_000 != 0) {
							if (dt5_0000 != 0) {
								if (dt6_00000 != 0) {
									sendABN_table.apply();
								}
							}
							else {
								if (dt6_00001 != 0) {
									sendABN_table.apply();
								}
							}
						}
						else {
							if (dt5_0001 == 0) {
								if (dt6_00011 != 0) {
									sendABN_table.apply();
								}
							}
						}
					}
					else {
						if (dt4_001 != 0) {
							if (dt5_0010 != 0) {
								if (dt6_00100 == 0) {
									sendABN_table.apply();
								}
							}
						}
						else {
							if (dt5_0011 != 0) {
								if (dt6_00110 != 0) {
									sendABN_table.apply();
								}
							}
							else {
								if (dt6_00111 != 0) {
									sendABN_table.apply();
								}
							}
						}
					}
				}
				else {
					if (dt3_01 != 0) {
						/*if (dt4_010 != 0) {
							if (dt5_0100 != 0) {
								sendABN_table.apply();
							}
						}
						else {
							if (dt5_0101 != 0) {
								if (dt6_01010 != 0) {
									sendABN_table.apply();
								}
							}
							else {
								if (dt6_01011 != 0) {
									sendABN_table.apply();
								}
							}
						}*/
						sendABN_table.apply();
					}
					else {
						if (dt4_011 != 0) {
							/*if (dt5_0110 != 0) {
								if (dt6_01100 != 0) {
									sendABN_table.apply();
								}
							}
							else {
								sendABN_table.apply();
							}*/
							sendABN_table.apply();
						}
						/*else {
							if (dt5_0111 != 0) {
								if (dt6_01111 == 0) {
									sendABN_table.apply();
								}
							}
						}*/
					}
				}
			}
			else {
				if (dt2_1 != 0) {
					if (dt3_10 != 0) {
						if (dt4_100 != 0) {
							/*if (dt5_1000 != 0) {
								if (dt6_10000 == 0) {
									sendABN_table.apply();
								}
							}
							else {
								if (dt6_10001 == 0) {
									sendABN_table.apply();
								}
							}*/
						}
						else {
							if (dt5_1001 != 0) {
								/*if (dt6_10010 != 0) {
									sendABN_table.apply();
								}*/
							}
							else {
								sendABN_table.apply();
							}
						}
					}
					/*else {
						if (dt4_101 != 0) {
							sendABN_table.apply();
						}
						else {
							if (dt5_1011 != 0) {
								sendABN_table.apply();
							}
						}
					}*/
				}
				else {
					if (dt3_11 != 0) {
						if (dt4_110 != 0) {
							if (dt5_1100 != 0) {
								if (dt6_11000 == 0) {
									sendABN_table.apply();
								}
							}
						}
						/*else {
							if (dt5_1101 != 0) {
								if (dt6_11011 != 0) {
									sendABN_table.apply();
								}
							}
						}*/
					}
					else {
						/*if (dt4_111 != 0) {
							if (dt5_1111 != 0) {
								sendABN_table.apply();
							}
						}*/
						sendABN_table.apply();
					}
				}
			}

		}
		else if (hdr.ipv4.isValid()) {
			// 处理非udp和tcp的初始流量，仅保留ip包头
			//sendABN_table.apply();
			sendNRM(12);
		}
		hdr.sketch.setInvalid();
	}
}

/* Egress Pipeline */
control Egress(inout egress_headers_t hdr,
	inout egress_metadata_t meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
	/* 4字节对齐填充处理表 */
	action padding1() {
		hdr.padding_1.setValid();
		hdr.padding_1.buf = 0;
		hdr.info.subLen = 4;
		hdr.oldipv4.total_len = 21;
	}
	action padding2() {
		hdr.padding_2.setValid();
		hdr.padding_2.buf = 0;
		hdr.info.subLen = 4;
		hdr.oldipv4.total_len = 22;
	}
	action NoPadding() {
		hdr.oldipv4.total_len = hdr.info.subLen+20;
	}
	table padding_table {
		actions = {
			padding1;
			padding2;
			NoPadding;
		}
		key = {
			hdr.info.subLen: exact;
		}
		size = 2;
		default_action = NoPadding;
	}

	/* RDMA包的定值填充部分 */
	action setConst() {
		//hdr.ethernet.dstAddr = 0xffffffffffff;
		//hdr.ethernet.srcAddr = 0x1070fd31ec7d;
		hdr.ethernet.etherType = 0x0800;

		hdr.newipv4.setValid();
		hdr.newipv4.version			= 4;
		hdr.newipv4.ihl 			= 5;
		hdr.newipv4.diffserv 		= 2;
		hdr.newipv4.total_len 		= hdr.info.subLen+80;
		//hdr.newipv4.identification	= 0;
		hdr.newipv4.flags 			= 2;
		hdr.newipv4.fragOffset 		= 0;
		hdr.newipv4.ttl 			= 64;
		hdr.newipv4.protocol 		= 17;
		hdr.newipv4.checksum     	= 0;
		//hdr.newipv4.srcAddr 			= 0x0a000001;
		//hdr.newipv4.dstAddr 			= 0x0a000002;

		hdr.udp.setValid();
		//hdr.udp.src_port = 0;
		hdr.udp.dst_port = 4791;
		hdr.udp.len = hdr.info.subLen+60;
		hdr.udp.checksum = 0;

		hdr.ib_bth.setValid();
		hdr.ib_bth.opcode = 10;
		hdr.ib_bth.event = 0;
		hdr.ib_bth.migReq = 1;
		hdr.ib_bth.padCount = 0;
		hdr.ib_bth.version = 0;
		hdr.ib_bth.pkey = 0xffff;
		hdr.ib_bth.resv8a = 0;
		//hdr.ib_bth.dstQP = 0;
		hdr.ib_bth.ackReq = 1;
		hdr.ib_bth.resv7b = 0;
		//hdr.ib_bth.psn = 0;

		hdr.ib_reth.setValid();
		hdr.ib_reth.va = 0;
		hdr.ib_reth.rkey = 0;
		hdr.ib_reth.length[15:0] = hdr.info.subLen+20;
		hdr.ib_reth.length[31:16] = 0;
		//hdr.ib_reth.length = (bit<32>)hdr.info.subLen+20;

		hdr.ib_icrc.setValid();
		hdr.ib_icrc.val = 0;

		hdr.eth_crc.setValid();
		hdr.eth_crc.val = 0;

		meta.tmp0 = (bit<32>)hdr.oldipv4.total_len;
	}
	table setConst_table {
		actions = {
			setConst;
		}
		size = 1;
		const default_action = setConst;
	}

	/* ipv4/RDMA包序号计数器 */
	Register<bit<32>, bit<1>>(1) seq_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(seq_reg) seqAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			rst = reg;
			reg = reg+1;
        }
    };
	action seqAdd() {
		meta.tmp1 = seqAdd_action.execute(0);
		hdr.newipv4.identification = (bit<16>)meta.tmp1;
		hdr.ib_bth.psn = (bit<24>)meta.tmp1;
	}
	table seqAdd_table {
		actions = {
			seqAdd;
		}
		size = 1;
		const default_action = seqAdd;
	}

	/* 虚拟地址低位加法器（2组）
	 * 用于计算写入虚拟地址的低32位值
	 */
	Register<bit<32>, bit<1>>(2) va_lo_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(va_lo_reg) loAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
            rst = reg;
			reg = reg + meta.tmp0;
        }
    };
	action loAdd() {
		meta.tmp1 = loAdd_action.execute(hdr.info.idx);
		hdr.ib_reth.va[31:0] = meta.tmp1;
	}
	table loAdd_table {
		actions = {
			loAdd;
		}
		size = 1;
		const default_action = loAdd;
	}

	/* 虚拟地址进位加法器（2组）
	 * 用于计算低32位地址是否发生进位
	 */
	Register<b32_carry_t, bit<1>>(2) va_cr_reg;
    RegisterAction<b32_carry_t, bit<1>, bit<32>>(va_cr_reg) crCal_action = {
        void apply(inout b32_carry_t reg, out bit<32> flag) {
			flag = 0;
			if (reg.oldVal >= 0x80000000 && reg.newVal < 0x80000000) {
				flag = 1;
			}
			reg.oldVal = reg.newVal;
			reg.newVal = reg.newVal + meta.tmp0;
        }
    };
	action crCal() {
		meta.tmp0 = crCal_action.execute(hdr.info.idx);
	}
	table crCal_table {
		actions = {
			crCal;
		}
		size = 1;
		const default_action = crCal;
	}

	/* 虚拟地址高位加法器（2组）
	 * 用于计算写入虚拟地址的高32位值
	 */
	Register<bit<32>, bit<1>>(2) va_hi_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(va_hi_reg) hiAdd_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			reg = reg + meta.tmp0;
			rst = reg;
        }
    };
	action hiAdd() {
		meta.tmp1 = hiAdd_action.execute(hdr.info.idx);
		hdr.ib_reth.va[63:32] = meta.tmp1;
	}
	table hiAdd_table {
		actions = {
			hiAdd;
		}
		size = 1;
		const default_action = hiAdd;
	}

	/* RDMA的变量填充部分，数据来源于控制平面端文件 */
	action setVar(bit<48> dstEth, bit<48> srcEth, bit<32> srcIP, bit<32> dstIP, bit<16> srcPort, bit<24> dstQP, bit<32> rkey) {
		hdr.ethernet.dstAddr = dstEth;
		hdr.ethernet.srcAddr = srcEth;
		hdr.newipv4.srcAddr = srcIP;
		hdr.newipv4.dstAddr = dstIP;
		hdr.udp.src_port = srcPort;
		hdr.ib_bth.dstQP = dstQP;
		hdr.ib_reth.rkey = rkey;
	}
	table setVar_table {
		actions = {
			NoAction;
			setVar;
		}
		key = { hdr.info.type: exact; }
		size = 2;
		default_action = NoAction;
	}

	/* 用于删去特定子包，以便剩余部分进入回环再次切分 */
	action delSubpkg() {
		hdr.oldipv4.total_len = hdr.oldipv4.total_len-hdr.info.subLen;
		hdr.subpkg_256.setInvalid();
		hdr.subpkg_128.setInvalid();
		hdr.subpkg_64.setInvalid();
		hdr.subpkg_32.setInvalid();
		hdr.subpkg_16.setInvalid();
		hdr.subpkg_8.setInvalid();
		hdr.subpkg_4.setInvalid();
		hdr.subpkg_2.setInvalid();
		hdr.subpkg_1.setInvalid();
	}
	table delSubpkg_table {
		actions = {
			delSubpkg;
		}
		size = 1;
		const default_action = delSubpkg;
	}

	// 用于记录正常包大小的寄存器，供测试用
	Register<bit<32>, bit<1>>(1) NRMsz_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(NRMsz_reg) NRMsz_action = {
		void apply(inout bit<32> reg) {
			reg = reg + meta.tmp0;
		}
	};
	action NRMszCnt() {
		NRMsz_action.execute(0);
	}
	table NRMszCnt_table {
		actions = {
			NRMszCnt;
		}
		size = 1;
		const default_action = NRMszCnt;
	}

	// 用于记录正常包数量的寄存器，供测试用
	Register<bit<32>, bit<1>>(1) NRM_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(NRM_reg) NRM_reg_action = {
		void apply(inout bit<32> reg) {
			reg = reg + 1;
		}
	};
	action NRMCnt() {
		NRM_reg_action.execute(0);
	}
	table NRMCnt_table {
		actions = {
			NRMCnt;
		}
		size = 1;
		const default_action = NRMCnt;
	}

	// 用于记录异常包大小的寄存器，供测试用
	Register<bit<32>, bit<1>>(1) ABNsz_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(ABNsz_reg) ABNsz_action = {
		void apply(inout bit<32> reg) {
			reg = reg + meta.tmp0;
		}
	};
	action ABNszCnt() {
		ABNsz_action.execute(0);
	}
	table ABNszCnt_table {
		actions = {
			ABNszCnt;
		}
		size = 1;
		const default_action = ABNszCnt;
	}

	// 用于记录正常包增量大小的寄存器，供测试用
	Register<bit<32>, bit<1>>(1) ABNex_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(ABNex_reg) ABNex_action = {
		void apply(inout bit<32> reg) {
			reg = reg + meta.tmp0;
		}
	};
	action ABNexCnt() {
		ABNex_action.execute(0);
	}
	table ABNexCnt_table {
		actions = {
			ABNexCnt;
		}
		size = 1;
		const default_action = ABNexCnt;
	}

	// 用于记录异常包数量的寄存器，供测试用
	Register<pair_32, bit<1>>(1) ABN_reg;
	RegisterAction<pair_32, bit<1>, bit<32>>(ABN_reg) ABN_reg_action = {
		void apply(inout pair_32 reg) {
			reg.left = reg.left + 1;
			if (hdr.oldipv4.total_len == 20) {
				reg.right = reg.right + 1;
			}
		}
	};
	action ABNCnt() {
		ABN_reg_action.execute(0);
	}
	table ABNCnt_table {
		actions = {
			ABNCnt;
		}
		size = 1;
		const default_action = ABNCnt;
	}

	// 用于记录正常包原始大小的寄存器，供测试用
	Register<bit<32>, bit<1>>(1) NRMin_reg;
	RegisterAction<bit<32>, bit<1>, bit<32>>(NRMin_reg) NRMin_action = {
		void apply(inout bit<32> reg) {
			reg = reg + (bit<32>)hdr.oldipv4.total_len;
		}
	};
	action NRMinCnt() {
		NRMin_action.execute(0);
	}
	table NRMinCnt_table {
		actions = {
			NRMinCnt;
		}
		size = 1;
		const default_action = NRMinCnt;
	}

	// 序号修正函数，接收到NAK后执行，修正发包序号，保证系统继续运作
	RegisterAction<bit<32>, bit<1>, bit<32>>(seq_reg) seqMod_action = {
        void apply(inout bit<32> reg, out bit<32> rst) {
			rst = reg; 
			reg = meta.tmp2;
        }
    };
	action seqMod() {
		meta.tmp3 = seqMod_action.execute(0);
	}
	table seqMod_table {
		actions = {
			seqMod;
		}
		size = 1;
		const default_action = seqMod;
	}

	// 记录丢包次数和数量的寄存器
	Register<pair_32, bit<1>>(1) lost_reg;
	RegisterAction<pair_32, bit<1>, bit<32>>(lost_reg) lostCnt_action = {
		void apply(inout pair_32 reg) {
			reg.left = reg.left + 1;
			reg.right = reg.right + meta.tmp3;
		}
	};
	action lostCnt() {
		lostCnt_action.execute(0);
	}

	apply {
		if (hdr.info.type == 3 || hdr.info.type == 4) {
			/* 如果是异常包的镜像，或者正常包的输出包头，进行RDMA封装操作 */
			
			padding_table.apply();	// 4字节对齐填充预处理

			setConst_table.apply();	// 填充定值
			setVar_table.apply();	// 填充每次任务不同的特定变值

			seqAdd_table.apply();	// 计算序列号
			loAdd_table.apply();	// 计算低位
			crCal_table.apply();	// 计算进位
			hiAdd_table.apply();	// 计算高位
		}
		else if (hdr.info.type == 2) {
			/* 来自回环端口的正常包包头，进行变量修改后发出，回环后type变为4写入远端 */
			hdr.oldipv4.total_len = min(1500, hdr.oldipv4.total_len);
			/* 正常包输入大小记录 */
			NRMinCnt_table.apply();
			if (hdr.udp_payload.isValid()) {
				hdr.oldipv4.total_len = 28;
				meta.tmp0 = 28;
			}
			else if (hdr.tcp_payload.isValid()) {
				hdr.oldipv4.total_len = 40;
				meta.tmp0 = 40;
			}
			else {
				hdr.oldipv4.total_len = 20;
				meta.tmp0 = 20;
			}
			/* 正常包包头大小记录 */
			NRMszCnt_table.apply();
			/* 正常包数+输出正常包数 */
			NRMCnt_table.apply();
		}
		else if (hdr.info.type == 1) {
			/* 如果是异常包原像，丢弃相应子包 */
			meta.tmp0[31:16] = 0;
			meta.tmp0[15:0] = hdr.oldipv4.total_len;
			/* 回环 */
			ABNexCnt_table.apply();
			/* 输出大小 */
			meta.tmp0[15:0] = hdr.info.subLen+80;
			ABNszCnt_table.apply();
			delSubpkg_table.apply();
			/* 异常包数+输出异常包数 */
			ABNCnt_table.apply();
		}
		else if (hdr.info.type == 0 && hdr.ethernet.etherType == (bit<16>)ether_type_t.IPV4) {
			// 根据MTU限制长度
			hdr.oldipv4.total_len = min(1500, hdr.oldipv4.total_len);

			if (hdr.ib_aeth.isValid() && hdr.ib_aeth.syndrome != 0) {
				/* 如果检测到NAK包，立即进行序号修正 */
				meta.tmp2 = (bit<32>)hdr.ib_bth_msg.psn;
				seqMod_table.apply();
				meta.tmp3 = meta.tmp3 - meta.tmp2;
				meta.tmp3 = meta.tmp3 & 0xffffff;
				// 进行丢包记录
				lostCnt();
			}
		}
		hdr.info.setInvalid();
	}
}

/* main */
Pipeline(
	IngressParser(),
	Ingress(),
	IngressDeparser(),
	EgressParser(),
	Egress(),
	EgressDeparser()
) pipe;

Switch(pipe) main;