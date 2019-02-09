###iptables

####任务描述  

1. 了解iptables配置规则及语法，确定新消息iptables消息结构（以下简称IPT消息）。
2. 在ovs中定义IPT消息，定义消息解析处理函数。需要修改的文件有：
	* include/openflow/openflow-1.3.h
	* lib/ofp-msg.h 
	* lib/ofp-util.h 
	* ofproto/ofproto.c
3. 对于IPT消息修改ryu代码。需要修改的文件有：
	* ofproto\_v1\_3.py
	* ofproto\_v1\_3_parser.py
4. 编写ryu应用，功能是向ovs发送IPT消息，进行指定的iptables的配置。
5. ovs解析的两种思路：
	* 在ovs里完全解析IPT消息，调用iptables接口，填写配置参数，直接发给iptables，这样对iptables的处理过程就无需修改
	* 在ovs里解析出IPT消息中的目标的ip和port信息，将整个消息发送给对应的iptables，然后iptables对消息再一次解析，得到配置信息。


既然要借助oxm来实现，对于消息flow_mod定义及处理过程的分析是很有必要的.



#### Question
* 实际上在controller中处理操作如下描述，处理有：ACCEPT,DROP,QUEUE和RETURN，但是我了解道德操作类型是ACCEPT,DROP,REJECT最多再有一个LOG。

		typedef enum _action_description{
		    DESC_NONE,
		    ACCEPT,
		    DROP,
		    QUEUE,
		    RETURN
		}ActionDesc;
至少在controller中，所能解析的参数是少于iptables可以使用的参数的。
* 虽然采取了tlv格式来承载传递中的消息，但是在消息到ovs后解析的时候还是需要一个有所有匹配与的结构体来get这些。这个是不是要自定义啊。应该要自定义吧。
* 嗯还是觉得挺复杂的。
* 掩码的话可以直接输1的位数，会容易转换一点。
* 在对一个union类型进行memcpy的时候，是从哪一端开始拷贝？例如

	     union mf_value {
	         uint8_t tun_metadata[128];
	         struct in6_addr ipv6;
	         struct eth_addr mac;
	         ovs_be128 be128;
	         ovs_be64 be64;
	         ovs_be32 be32;
	         ovs_be16 be16;
	         uint8_t u8;
	     };
	     memcpy(value, payload, payload_len);
当payload_len = 8时，拷贝到u8？

#### 实验设计
首先是消息设计：

1. IPT消息中固定字段中包含iptables目的地址和端口。
2. 使用oxm匹配的项有：表名，命令，优先级，链名，动作，表项index，目的IP，源IP，目的IP掩码，源IP掩码，协议，目的端口，源端口。其中，可能有端口范围匹配，如果oxm中连续遇到两个匹配域为同种端口的情况则是端口范围匹配，分别为起止端口。




#### 操作
* 首先先给新消息起个名字，就叫MSG_IPTABLES好了，lib/ofp-msg.h。

		//ofpraw:
		/* OFPT 1.3+ (36): struct ofp13_msg_iptables. */
	    OFPRAW_OFPT13_MSG_IPTABLES,
	    
	    //ofptype:
	    OFPTYPE_MSG_IPTABLES, 
* 消息结构的话，好像有点难，毕竟变长。

		struct ofp13_msg_iptables{
			ovs_be32 dip;  		//目标iptables的通信地址
			ovs_be16 dport;		//目标iptables的通信端口
			uint8_t pad[2]; 
		};
		//OFP_ASSERT(sizeof(struct ofp13_msg_iptables) == 8);
		
		//匹配项
		enum oxm_mit_match_fields {
			MITP_TABLE_NAME		= 44,
			MITP_COMMAND			= 45,
			MITP_PRIORITY			= 46,
			MITP_CHAIN_NAME		= 47,
			MITP_ACTION			= 48,
			MITP_INDEX			= 49,
			MITP_SOURCE_IP		= 50,
			MITP_DEST_IP			= 51,
			MITP_SOURCE_IP_MASK	= 52,
			MITP_DEST_IP_MASK	= 53,
			MITP_PROTO			= 54,
			MITP_SOURCE_PORT1	= 55,
			MITP_SOURCE_PORT2	= 56,
			MITP_DEST_PORT1		= 57,
			MITP_DEST_PORT2		= 58,
		};
		
		
		
* 修改一下nx-match.c，增加一个oxm class ID：

		enum ofp12_oxm_class {
		    OFPXMC12_NXM_0          = 0x0000, /* Backward compatibility with NXM */
		    OFPXMC12_NXM_1          = 0x0001, /* Backward compatibility with NXM */
		    OFPXMC12_OPENFLOW_BASIC = 0x8000, /* Basic class for OpenFlow */
		    OFPXMC15_PACKET_REGS    = 0x8001, /* Packet registers (pipeline fields). */
		    OFPXMC12_IPTABLES_BASIC = 0X8002, /* Basic class for iptables */
		    OFPXMC12_EXPERIMENTER   = 0xffff, /* Experimenter class */
		};
这一步同时要修改ryu的oxm\_fields.py，以及同样地修改ofproto\_v1\_3.py，如果乐意的话还有ofproto\_v1\_4.py和ofproto\_v1\_5.py，添加：  
 
		# enum ofp_match_type
		OFPXMC_IPTABLES_BASIC = 0X8002
在ofproto\_v1\_3.py中，需要定义以下函数（参考了OFPXMC\_OPENFLOW\_BASIC类型的函数）（像是消息拼装函数）：

		def oxm_tlv_header_ipt(field, length):
		    return _oxm_tlv_header(OFPXMC_IPTABLES_BASIC, field, 0, length)

* 在lib/ofp-util.h 中添加相应的数据结构代表对应的通用类型结构，因为ovs用户空间在解码相应的消息的时候需要针对具体的类型执行相应的动作，所以也要更新 ofp-actions.h
		
		//解码辅助结构，基本参考消息结构ofp13_msg_iptables
		struct ofputil_msg_iptables {
			ovs_be32 dip;  		//目标iptables的通信地址
			ovs_be16 dport;		//目标iptables的通信端口
			struct mitmatch match;	//匹配项
		};
		struct mitmatch{
			TableName tablename;		//表名
			CommandList command;//命令
			uint8_t priority; 	//优先级，0-99
			ChainName chainname;		//链名
			ActionDesc action;	//动作
			ovs_be16 index;		//索引
			ovs_be32 ip_src; 	//源IP
			ovs_be32 ip_dst; 	//目的IP
			ovs_be32 ipm_src;	//源IP掩码
			ovs_be32 ipm_dst; 	//目的IP掩码
			ovs_be16 tp_src[2]; //源端口
			ovs_be16 tp_dst[2]; //目的端口
			ProtoType proto;		//协议
		};
		
		
		
		//解码辅助函数
		enum ofperr ofputil_decode_msg_iptables(struct ofputil_msg_iptables *mit, 
						const struct ofp_header *oh,
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table);
		//编码辅助函数
		struct ofpbuf *ofputil_encode_msg_iptables(const struct ofp_header *oh, struct ofputil_msg_iptables *m);


		struct ofpact_msg_iptables {
		    struct ofpact ofpact;
		    uint32_t vector;
		};

* 添加枚举类型

		typedef enum _action_description{
		    DESC_NONE,
		    ACCEPT,
		    REJECT,
		    DROP
		}ActionDesc;//动作
		typedef enum _chain_name{
		    TYPE_NONE,
		    PREROUTING,
		    INPUT,
		    OUTPUT,
		    FORWARD,
		    POSTROUTING
		}ChainName;//链名
		typedef enum _command_list{
			SET_POLICY,
			APPEND,
			REPLACE,
			DELETE,
			CLEAN,
			ALLIN
		}CommandList;//命令
		typedef enum _proto_type{
		    PROTO_NONE,
		    TCP,
		    UDP,
		    ARP,
		    ICMP
		}ProtoType;//协议
		typedef enum _table_name{
		    NAME_NONE,
			filter,
			nat,
			mangle
		}TableName;//表名



#### ryu的修改
通过ryu来构造ipt消息是比较容易的。

|  消息结构       |说明    |
|  ------------:| -----:|
| 32bit dip     |
| 16bit dport   |
| 8x2bit pad    |
| 16bit type    |ofp_match匹配类型
| 16bit length  |长度
| oxm fleid[0]  |多个oxm匹配域
|  pad          |填充，数量不确定

* ofproto\_v1\_3.py

		OFPT_MSG_IPTABLES = 36
		
		# struct ofp_msg_iptables
		_OFP_MSG_IPTABLES_PACK_STR0 = 'IH2x'
		OFP_MSG_IPTABLES_STR = '!' + _OFP_MSG_IPTABLES_PACK_STR0 + _OFP_MATCH_PACK_STR
		OFP_MSG_IPTABLES_STR0 = '!' + _OFP_MSG_IPTABLES_PACK_STR0
		
		OFP_MSG_IPTABLES_SIZE = 24
		assert (calcsize(OFP_MSG_IPTABLES_STR) + OFP_MATCH_SIZE + OFP_HEADER_SIZE == OFP_MSG_IPTABLES_SIZE)
添加枚举类型
	
		# enum iptables actions 
		DESC_NONE = 0
		ACCEPT = 1
		DROP = 2
		QUEUE = 3
		RETURN = 4
		# enum iptables chain name
		TYPE_NONE = 0
		PREROUTING = 1
		INPUT = 2
		OUTPUT = 3
		FORWARD = 4
		POSTROUTING = 5
		# enum iptables command list
		SET_POLICY = 0
		APPEND = 1
		ALTER = 2
		DELETE = 3
		CLEAN = 4
		ALLIN = 5
		# enum iptables proto type
		PROTO_NONE = 0
		TCP = 1
		UDP = 2
		ARP = 3
		ICMP = 4
		# enum iptables table name
		NAME_NONE = 0
		filter = 1
		nat = 2
		mangle = 3

ofp_match的结构（这个不用添加）

		# struct ofp_match
		_OFP_MATCH_PACK_STR = 'HHBBBB'
		OFP_MATCH_PACK_STR = '!' + _OFP_MATCH_PACK_STR
		OFP_MATCH_SIZE = 8
		assert calcsize(OFP_MATCH_PACK_STR) == OFP_MATCH_SIZE
		
添加types

		oxm_types = [
		    oxm_fields.IPTablesBasic('table_name', 44, type_desc.Int1),
		    oxm_fields.IPTablesBasic('command', 45, type_desc.Int1),
		    oxm_fields.IPTablesBasic('priority', 46, type_desc.Int1),
		    oxm_fields.IPTablesBasic('chain_name', 47, type_desc.Int1),
		    oxm_fields.IPTablesBasic('action', 48, type_desc.Int1),
		    oxm_fields.IPTablesBasic('index', 49, type_desc.Int2),
		    oxm_fields.IPTablesBasic('source_ip', 50, type_desc.IPv4Addr),
		    oxm_fields.IPTablesBasic('dest_ip', 51, type_desc.IPv4Addr),
		    oxm_fields.IPTablesBasic('source_ip_mask', 52, type_desc.IPv4Addr),
		    oxm_fields.IPTablesBasic('dest_ip_mask', 53, type_desc.IPv4Addr),
		    oxm_fields.IPTablesBasic('proto', 54, type_desc.Int1),
		    oxm_fields.IPTablesBasic('source_port1', 55, type_desc.Int2),
		    oxm_fields.IPTablesBasic('source_port2', 56, type_desc.Int2),
		    oxm_fields.IPTablesBasic('dest_port1', 57, type_desc.Int2),
		    oxm_fields.IPTablesBasic('dest_port2', 58, type_desc.Int2),    
		] + nicira_ext.oxm_types
		
		
		
		def oxm_tlv_header_ipt(field, length):
    		return _oxm_tlv_header(OFPXMC_IPTABLES_BASIC, field, 0, length)
    		
    		
* oxm_fields.py

		class OpenFlowBasic(_OxmClass):
			_class = OFPXMC_OPENFLOW_BASIC
		class IPTablesBasic(_OxmClass):
			_class = OFPXMC_IPTABLES_BASIC
   			
* ofproto\_v1\_3\_parser.py 


		@_register_parser
		@_set_msg_type(ofproto.OFPT_MSG_IPTABLES)
		class OFPMsgIPTable(MsgBase):
			"""docstring for OFPMsgIPTable.
			================ ======================================================
			Attribute        Description
			================ ======================================================
			dip
			dport
			match            Instance of ``OFPMatch``
			================ ======================================================
		
		
			"""
			def __init__(self, datapath, dip, dport, match=None):
				super(OFPMsgIPTable, self).__init__(datapath)
				self.dip = dip
				self.dport = dport
				if match is None:
					match = OFPMatch()
				assert isinstance(match, OFPMatch)
				self.match = match
		
			def _serialize_body(self):
				msg_pack_into(ofproto.OFP_MSG_IPTABLES_STR0, self.buf, ofproto.OFP_HEADER_SIZE, self.dip, self.dport)
				offset = (ofproto.OFP_MSG_IPTABLES_SIZE - ofproto.OFP_MATCH_SIZE)
				self.match.serialize(self.buf, offset)
		
			def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
				msg = super(OFPMsgIPTable, cls).parser(datapath, version, 
								msg_type, msg_len, xid, buf)
				(msg.dip, msg.dport) = struct.unpack_from(
								ofproto.OFP_MSG_IPTABLES_STR0, msg.buf,
								ofproto.OFP_HEADER_SIZE)
				offset = ofproto.OFP_MSG_IPTABLES_SIZE - ofproto.OFP_HEADER_SIZE
		
				try:
					msg.match = OFPMatch.parser(buf, offset)
				except exception.OFPTruncatedMessage as e:
					msg.match = e.ofpmsg
					e.ofpmsg = msg
					raise e
				return msg


#### ovs编译遇到的问题
* 报错conflicting types for  
由于新增了几个函数，这些函数除了在.c文件中定义之外，有的函数还需要在相应的.h文件中声明，以便被调用。但是在这些.h文件中，一些函数的参数类型可能还没有定义和声明，所以要在.h文件的开始部分声明参数类型。  
实际操作中就是添加`struct mitmatch`
