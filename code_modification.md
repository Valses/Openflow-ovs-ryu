## 新增openflow消息实现远程防火墙配置实验——修改函数

by zhangyaxin  
2017.8.7

### ovs部分
* 在include/openflow/openflow-1.3.h中扩展of协议，增加新的消息类型ofp13\_msg\_iptables和ofp13\_error\_iptables，一个是配置信息消息体，一个是反馈信息消息体。

		struct ofp13_msg_iptables{
			ovs_be32 dip;  		//目标iptables的通信地址
			ovs_be16 dport;		//目标iptables的通信端口
			uint8_t pad[2]; 
		};
		OFP_ASSERT(sizeof(struct ofp13_msg_iptables) == 8);
		struct ofp13_error_iptables{
		    ovs_be16 type;
		    ovs_be16 code;
		    uint8_t data[0];
		};
		OFP_ASSERT(sizeof(struct ofp13_error_iptables) == 4);
		
* 在lib/ofp-msg.h中，更新ofpraw结构体和ofptype枚举体。需要注意的是对ofpraw的更改__包括注释__一定要遵循固定的格式，会在解析的时候用到注释：   

		/* OFPT 1.3+ (36): struct ofp13_msg_iptables, uint8_t[8][]. */
		OFPRAW_OFPT13_MSG_IPTABLES,
		/* OFPT 1.3+ (37): struct ofp13_error_iptables, uint8_t[]. */
		OFPRAW_OFPT13_ERROR_IPTABLES,
	    
	    //ofptype:
	    OFPTYPE_MSG_IPTABLES,			/* OFPRAW_OFPT13_MSG_IPTABLES. */
		OFPTYPE_ERROR_IPTABLES,			/* OFPRAW_OFPT13_ERROR_IPTABLES. */
	   
* 修改一下nx-match.c，增加一个oxm class ID。

		enum ofp12_oxm_class {
		    OFPXMC12_NXM_0          = 0x0000, /* Backward compatibility with NXM */
		    OFPXMC12_NXM_1          = 0x0001, /* Backward compatibility with NXM */
		    OFPXMC12_OPENFLOW_BASIC = 0x8000, /* Basic class for OpenFlow */
		    OFPXMC15_PACKET_REGS    = 0x8001, /* Packet registers (pipeline fields). */
		    OFPXMC12_IPTABLES_BASIC = 0X8002, /* Basic class for iptables */
		    OFPXMC12_EXPERIMENTER   = 0xffff, /* Experimenter class */
		};
* 在 lib/ofp-util.h 中添加相应的数据结构代表对应的通用类型结构，当接受到控制器发来的IPT消息后，将解析消息的结果存放在ofputil_msg_iptables结构体中，整体借用的是ruletables里的结构struct handle。
	
		//解码辅助结构ofputil_msg_iptables
		typedef struct basic_header{
		    uint32_t s_addr,d_addr;
		    uint32_t smsk,dmsk;
		    uint16_t spts[2];
		    uint16_t dpts[2];
		    ProtoType proto;
		}basic_header;
		typedef struct properties{
		    TableName tablename;
		}properties;
		struct list_head {
		    struct list_head *next, *prev;
		};
		typedef struct ruletable {
		    basic_header head;
		    uint8_t priority;
		    ChainName chainName;
		    ActionDesc actionDesc;
		    properties property;
		    struct list_head list;//链表结构体一定要放在结构体最下面
		}ruletable;
		struct handle{
		    uint32_t index;
		    CommandList command;
		    ruletable table;
		};
		struct ofputil_msg_iptables {
		    ovs_be32 dip;
		    ovs_be16 dport;
		    struct handle match;
		};
		
		//解码函数ofputil_decode_msg_iptables
		enum ofperr ofputil_decode_msg_iptables(struct ofputil_msg_iptables *mit,const struct ofp_header *oh);
		//编码辅助函数
		struct ofpbuf *
		make_error_iptables(char *s);

* 在 lib/ofp-util.h 中添加枚举类型，这个是借鉴ruletables中的枚举类型，但是对动作ActionDesc做了修改，因为查到的iptables的动作常用的是ACCEPT、REJECT和DROP，且将CommandList中的ALTER修改为REPLACE，因为觉得 -r 更像REPLACE。然后这个随时可以扩展。

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
* 修改ofproto/ofproto.c中的handle\_openflow__函数，在switch-case中添加对新消息的判断处理分支：

		case OFPTYPE_MSG_IPTABLES:
			return handle_msg_iptables(ofconn, oh);
		
* __msg\_iptables配置过程__：添加了一系列对IPT消息的解码和处理函数，下面只给出函数名和添加位置，具体函数在文件fuctions.c中。同时，会被其他文件中函数调用的函数需要**在相应的头文件中声明**。 
	* 在文件ofproto/ofproto.c中添加: 
			
			//IPT消息处理函数
			static enum ofperr
			handle_msg_iptables(struct ofproto *ofproto, const struct ofp_header *oh);
			//解码完成后IPT消息执行函数
			static enum ofperr handle_msg_iptables__
			(struct ofproto *ofproto, struct ofputil_msg_iptables *mit)
			//将mit中的信息转化为iptables命令行参数
			static int to_argv(struct ofputil_msg_iptables *mit,char * argv[])
			//将消息send给中间模块
			static void send_message_to_my_mod(char *msg, struct ofputil_msg_iptables *mit)
	* 在文件lib/ofp-util.c中添加：
	
			//IPT消息解码函数
			enum ofperr 
			ofputil_decode_msg_iptables(struct ofputil_msg_iptables *mit,
                            const struct ofp_header *oh,
                            struct ofpbuf *ofpacts,
                            ofp_port_t max_port, uint8_t max_table);
          
			//获取match的数据，对match头进行判断
			enum ofperr 
			ofputil_pull_mit_match(struct ofpbuf *buf, 
							struct mitmatch *match, uint16_t *padded_match_len);
	* 在文件nx-match.c中添加：
			
			//整数字节提取所有的oxm字段
			static enum ofperr 
			oxm_pull_mit_match(struct ofpbuf *b, struct mitmatch *match);
			
			//对oxm字段进行循环判断，解析出匹配域和值，存储到match中
			static enum ofperr 
			nx_pull_mit_raw(const uint8_t *p, unsigned int match_len,
	                struct mitmatch *match);
	       
			//获取每一个中匹配域和具体匹配值
			static enum ofperr 
			nx_pull_mitmatch_entry(struct ofpbuf *b,
	                       enum oxm_mit_match_fields *mf,
	                       union mf_value *value);
	* 在文件meta-flow.c中添加：

			//将解析出的value赋值给match结构体
			uint32_t mf_set_mitmatch(enum oxm_mit_match_fields mf,
                         const union mf_value *value,
                         struct mitmatch *match);



* 下面的修改不是非常必要，不改也不会报错，但是也说明一下，以下函数中都有关于消息类型的switch-case选择，所以就在case中合适的位置添加了新消息。
	1. 修改了ofp-util.c中的函数static bool ofputil\_is\_bundlable  
	2. 修改了rconn.c中的函数static bool is\_admitted\_msg   
	3. 修改了learning-switch.c中的函数static void lswitch\_process\_packet

	
### ryu部分
ryu主要做了msg\_iptables的发送，error\_iptables的接受分析打印，发送的时候采用了RESTAPI。

特别注意缩进的对齐。  
需要修改的文件：  
	
	@_register_parser
	@_set_msg_type(ofproto.OFPT_MYMSGTYPE)
	class OFPMyMsgType(MsgBase):
		"""	
		test msg MyMsgType
	
	    ========== ==============================
	    Attribute  Description
	    ========== ==============================
	    types       
	    ========== ==============================
	    lens        
	    ========== ==============================
	
		"""
		def __init__(self, datapath, types=None, lens=None):
			super(OFPMyMsgType, self).__init__(datapath)
			self.types = types
			self.lens = lens
	
		@classmethod
		def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
			msg = super(OFPMYMSGTYPE, cls).parser(datapath, version, msg_type,
	                                      msg_len, xid, buf)
			offset = ofproto.OFP_HEADER_SIZE
			data = struct.unpack_from(ofproto.OFP_MYMSGTYPE_PACK_STR, msg.buf, offset)
			msg.data = data
			return msg
	
		def _serialize_body(self):
			msg_pack_into(ofproto.OFP_MYMSGTYPE_PACK_STR, self.buf, ofproto.OFP_HEADER_SIZE, self.types, self.lens)

			
ofproto\_v1\_3.py

		OFPT_MYMSGTYPE = 35
		OFP_MYMSGTYPE_PACK_STR = '!HH4x'
		OFP_MYMSGTYPE_SIZE = 16
		assert (calcsize(OFP_MYMSGTYPE_PACK_STR) + OFP_HEADER_SIZE == OFP_MYMSGTYPE_SIZE)

ofp\_handler.py（对于目前的测试来说这一步不需要）

	@set_ev_handler(ofp_event.EventOFPMyMsgType, MAIN_DISPATCHER)
	def mymsgtype_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        mymsg = datapath.ofproto_parser.OFPMyMsgType(datapath)
        mymsg.xid = msg.xid
        mymsg.data = msg.data
        datapath.send_msg(mymsg)
运行的时候报错有未对齐以及msg\_pack\_into的参数数量出错。  
修改完成后运行python setup.py install安装。



### ruletables部分
ruletables主要是修改了通信过程，本来ruletables是与一个编写好的controller通信的，现在需要和ovs通信。ruletables的通信端口是6666，ovs的对应通信端口是3333。
