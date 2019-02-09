# 新增openflow消息实现远程防火墙配置实验
by zhangyaxin  
2017.7.21
## 1. 任务描述
修改ovs源码，新增openflow消息来实现iptables的远程配置。  

1. 了解iptables配置规则及语法，确定新消息iptables消息结构（以下简称IPT消息）。
2. 修改ovs源码，在ovs中定义IPT消息和相关函数，实现对来自控制器ryu发送的IPT消息的解析和处理，使其能够进行iptables远程配置。
4. 修改ryu代码，编写ryu应用，实现向ovs发送指定的IPT消息，进行远程iptables的配置。

## 2. iptables原理	
#### 2.1 iptables基本工作原理

![text](img-folder/iptables_1.png)

五个钩子函数（hook functions）,也叫五个规则链。
  
1. PREROUTING：对数据包作路由选择前应用此链中的规则
2. INPUT：进来的数据包应用此规则链中的规则
3. FORWARD：转发数据包时应用此规则链中的规则
4. OUTPUT：外出的数据包应用此规则链中的规则
5. POSTROUTING：对数据包作路由选择后应用此链中的规则  

我们现在用的比较多个功能有3个表：

1. filter 定义允许或者不允许的
2. nat 定义地址转换的 
3. mangle功能:修改报文原数据  

此外还有一个表raw，决定数据包是否被状态跟踪机制处，不常用

1. filter可应用的链: INPUT ，FORWARD ，OUTPUT  
2. nat可应用的链: PREROUTING ，OUTPUT ，POSTROUTING，INPUT  
3. mangle可应用的链: PREROUTING，INPUT，FORWARD，OUTPUT，POSTROUTING
4. raw可应用的链: OUTPUT、PREROUTING

规则表之间的优先顺序：  
raw——>mangle——>nat——>filter


#### 匹配条件

基本匹配条件： 

* -s：源IP(!)    
* -d：目标IP(!)  
* -p：协议类型  tcp,udp,icmp,esp,ah,udplite,sctp,(mh,icmpv6)    
* -i：流入网卡接口，匹配流入的网卡名，所以只能用在PREROUTING，INPUT，FORWARD链  
* -o：输出网卡接口，用在FORWARD，OUTPUT，POSTROUTING链  

常用扩展匹配条件：

* tcp  
--dport,--sport：端口匹配，使用前必须指定-p
* multiport    
--dports,--sports：多端口匹配，端口之间逗号隔开  
* iprange  
--src-range  --dst-range   
example: `--src-range 192.168.1.1-192.168.1.100`
* string
根据数据包中的出现字符串过滤，有bm和kmp算法  
example: `--algo bm --string"google"`
* time  
根据时间区段匹配报文，比如只接收早九点到晚九点的报文，只接收周一到周五的报文等
* connlimit  
对单IP的并发连接数量进行限制
* limit
对报文到达速率进行限制

## 3. 系统设计
#### 3.1 基本设计
基本的设计是这样的，首先ryu构造IPT消息，发送给ovs，ovs收到之后首先解析消息类型，确定是IPT消息后将IPT配置参数解析出来，存放在一个match结构体中，然后，再将这个结构体转换成一个iptables的命令，例如：  
`iptables -t filter -A INPUT -j ACCEPT -d 192.168.0.0/24`  
然后，ovs将这一字符串发送给中间模块ruletables-service，中间模块再对此进行一个简短的解析，最后执行。  

#### 3.2 消息结构设计

1. IPT消息中固定字段中包含iptables目的地址和端口。
2. 使用oxm匹配的项有：表名，命令，优先级，链名，动作，表项index，目的IP，源IP，目的IP掩码，源IP掩码，协议，目的端口1，目的端口2，源端口1，源端口2。
<img src="img-folder/iptables_2.png" width = "390" height = "450" align=center />

## 4. 代码修改
#### 4.1 对ovs的修改

* 在include/openflow/openflow-1.3.h中扩展of协议，增加新的消息类型ofp13\_msg\_iptables。

		struct ofp13_msg_iptables{
			ovs_be32 dip;  		//目标iptables的通信地址
			ovs_be16 dport;		//目标iptables的通信端口
			uint8_t pad[2]; 
		};
		OFP_ASSERT(sizeof(struct ofp13_msg_iptables) == 8);
		
* 在lib/ofp-msg.h中，更新ofpraw结构体（当ovs收到来自controller的消息之后就会利用ofpraw里面格式化的定义来验证消息的有效性，从而进行后续处理）和ofptype枚举体。需要注意的是对ofpraw的更改__包括注释__一定要遵循固定的格式，会在解析的时候用到注释：   
`/* OFPT 1.3+ (36): struct ofp13_msg_iptables, uint8_t[8][]. */`
以上注释表示IPT消息适用于openflow1.3+版本，消息类型36，包含一个ofp13_msg_iptable结构和整数字节的多个oxm匹配项。

		//ofpraw:
		/* OFPT 1.3+ (36): struct ofp13_msg_iptables, uint8_t[8][]. */
	    OFPRAW_OFPT13_MSG_IPTABLES,
	    
	    //ofptype:
	    OFPTYPE_MSG_IPTABLES,		/* OFPRAW_OFPT13_MSG_IPTABLES. */
	   
* 修改一下nx-match.c，增加一个oxm class ID（但是这一步在具体的消息处理中其实没有用到）。

		enum ofp12_oxm_class {
		    OFPXMC12_NXM_0          = 0x0000, /* Backward compatibility with NXM */
		    OFPXMC12_NXM_1          = 0x0001, /* Backward compatibility with NXM */
		    OFPXMC12_OPENFLOW_BASIC = 0x8000, /* Basic class for OpenFlow */
		    OFPXMC15_PACKET_REGS    = 0x8001, /* Packet registers (pipeline fields). */
		    OFPXMC12_IPTABLES_BASIC = 0X8002, /* Basic class for iptables */
		    OFPXMC12_EXPERIMENTER   = 0xffff, /* Experimenter class */
		};
* 在 lib/ofp-util.h 中添加相应的数据结构代表对应的通用类型结构，当接受到控制器发来的IPT消息后，将解析消息的结果存放在ofputil_msg_iptables结构体中。
	
		//解码辅助结构ofputil_msg_iptables
		struct ofputil_msg_iptables {
			ovs_be32 dip;  		//目标iptables的通信地址
			ovs_be16 dport;		//目标iptables的通信端口
			struct mitmatch match;	//匹配项
		};
		struct mitmatch{
			TableName tablename;	//表名
			CommandList command;	//命令
			uint8_t priority; 		//优先级，0-99
			ChainName chainname;	//链名
			ActionDesc action;		//动作
			ovs_be16 index;			//索引
			ovs_be32 ip_src; 		//源IP
			ovs_be32 ip_dst; 		//目的IP
			ovs_be32 ipm_src;		//源IP掩码
			ovs_be32 ipm_dst; 		//目的IP掩码
			ovs_be16 tp_src[2]; 	//源端口
			ovs_be16 tp_dst[2]; 	//目的端口
			ProtoType proto;		//协议
		};
		//解码函数ofputil_decode_msg_iptables
		enum ofperr ofputil_decode_msg_iptables(struct ofputil_msg_iptables *mit, 
						const struct ofp_header *oh,
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table);
* 在 lib/ofp-util.h 中添加枚举类型，这个是借鉴学长代码中的类型，但是对动作ActionDesc做了修改，因为查到的iptables的动作常用的是ACCEPT、REJECT和DROP，且将CommandList中的ALTER修改为REPLACE，因为觉得 -r 更像REPLACE。然后这个随时可以扩展。

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
		
* 添加了一系列对IPT消息的解码和处理函数，下面只给出函数名和添加位置，具体函数在文件fuctions.c中。同时，会被其他文件中函数调用的函数需要**在相应的头文件中声明**。 
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
    以上新增函数的调用关系图如下：  
    <img src="img-folder/iptables_3.png" width = "500" height = "430" align=center/>

* 下面的修改不是非常必要，不改也不会报错，但是也说明一下，以下函数中都有关于消息类型的switch-case选择，所以就在case中合适的位置添加了新消息。
	1. 修改了ofp-util.c中的函数static bool ofputil\_is\_bundlable  
	2. 修改了rconn.c中的函数static bool is\_admitted\_msg   
	3. 修改了learning-switch.c中的函数static void lswitch\_process\_packet

#### 4.2 对ryu的修改
通过ryu来构造ipt消息是比较容易的，对ryu源码修改的内容也不是很多。  

* 在ofproto\_v1\_3.py中添加消息及结构。

		OFPT_MSG_IPTABLES = 36
		
		# struct ofp_msg_iptables
		_OFP_MSG_IPTABLES_PACK_STR0 = 'IH2x'
		OFP_MSG_IPTABLES_PACK_STR = '!' + _OFP_MSG_IPTABLES_PACK_STR0 + _OFP_MATCH_PACK_STR
		OFP_MSG_IPTABLES_PACK_STR0 = '!' + _OFP_MSG_IPTABLES_PACK_STR0
		
		OFP_MSG_IPTABLES_SIZE = 24
		assert (calcsize(OFP_MSG_IPTABLES_PACK_STR) + OFP_MATCH_SIZE +  == OFP_MSG_IPTABLES_SIZE)
* 修改ofproto\_v1\_3.py，以及同样地修改oxm\_fields.py，在enum ofp\_match\_type下新增：  
 
		# enum ofp_match_type
		OFPXMC_IPTABLES_BASIC = 0X8002
* 在ofproto\_v1\_3.py的oxm\_types中新增匹配域，直接添加到oxm\_types原有内容之后。

		oxm_types = [
			#...之前的oxm_types内容...
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
* 在oxm\_fields.py中添加类IPTablesBasic。

		class IPTablesBasic(_OxmClass):
			_class = OFPXMC_IPTABLES_BASIC
* 在ofproto\_v1\_3\_parser.py中添加类OFPMsgIPTable，也是参考其他消息类写的，对于parser函数我觉得在发送消息的时候是没有用到的，所以可能有问题但是并未影响测试。
		
		@_register_parser
		@_set_msg_type(ofproto.OFPT_MSG_IPTABLES)
		class OFPMsgIPTable(MsgBase):
			"""
			OFPMsgIPTable.
			================ ======================
			Attribute        Description
			================ ======================
			dip	             目标iptables的IP地址
			dport            目标iptables的端口
			match            匹配
			================ ======================
		
		
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
				msg_pack_into(ofproto.OFP_MSG_IPTABLES_PACK_STR0, self.buf, ofproto.OFP_HEADER_SIZE, self.dip, self.dport)
				offset = (ofproto.OFP_MSG_IPTABLES_SIZE - ofproto.OFP_MATCH_SIZE)
				self.match.serialize(self.buf, offset)
		
			def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
				msg = super(OFPMsgIPTable, cls).parser(datapath, version, 
								msg_type, msg_len, xid, buf)
				(msg.dip, msg.dport) = struct.unpack_from(
								ofproto.OFP_MSG_IPTABLES_PACK_STR0, msg.buf,
								ofproto.OFP_HEADER_SIZE)
				offset = ofproto.OFP_MSG_IPTABLES_SIZE - ofproto.OFP_HEADER_SIZE
		
				try:
					msg.match = OFPMatch.parser(buf, offset)
				except exception.OFPTruncatedMessage as e:
					msg.match = e.ofpmsg
					e.ofpmsg = msg
					raise e
				return msg
				
#### 4.3 对ruletables-service的修改
基于/ruletables/conn.c中的原有函数处理思路，修改了必要的部分。主要实现将接收到的来自ovs的消息处理，实现配置iptables。  
conn.c中的很多函数原来是和controller交流的，但是现在我们要和ovs交流，所以一些向上反馈信息的函数目前都没用了。

* 修改了do\_com\_controller函数中while(1)的部分:

		while(1){
	        if((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
	            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
	            continue;
	        }
			int len = 0;
			len = recv(connfd, recvBuf , MSG_SIZE, 0);
			printf("recvlen = %d\n",len);
			char iptables_message[MSG_SIZE] = {0};
	       if(!memcpy(iptables_message, recvBuf, len)){
				//alert_to_controller( "memcpy error : \n");
	       }
			printf("recvmsg = %s\n",iptables_message);
	    	send_to_kernel(iptables_message);
	    	close(connfd);
    	}
* 添加了函数to_argv2，将一句命令行命令拆分成参数。

		static int to_argv2(char *msg, char * argv[]){
			int i = 0;
			int argc = 0;
			int len = strlen(msg);
			char *p1 = msg;
			char *p2 = msg;
			while(*p1 != '\0'){
				while(*p1 != ' ' && *p1 != '\0')
					p1++;
				if(*p1 == ' '){
					*p1 = '\0';
					p1++;
					argv[argc++] = p2;
					p2 = p1;
					//printf("------: %s\n",argv[argc-1]);
				}
			}
			argv[argc++] = p2;
			return argc;
		}
* 修改了send\_to\_kernel的参数类型为char *型，以及将原来调用to\_argv函数的地方改成调用to\_argv2函数。
