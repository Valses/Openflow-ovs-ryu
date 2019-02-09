### 实现
在openflow中新增一个消息类型，使得控制器和交换机可以相互发送此消息，识别并做相应处理，消息可以很简单

---
ovs

* include/openswitch/ofp-msgs.h中定义了enum ofptype，of消息类型

|  of消息类型    | 说明     |
|  ------------ |:--------:|
| Features      |获取交换机特性|
| Configuration |配置Openflow交换机|

1. ofproto创建路径（实际为ofproto_dpif对象）  
	bridge\_run->bridge\_reconfigure->ofproto\_create->alloc
2. ofbundle创建路径  
    bridge\_run->bridge\_reconfigure->port\_configure->ofproto\_bundle\_register->bundle\_set
3. ofport创建路径  
    bridge\_run->bridge\_reconfigure->ofproto\_create->alloc
4. xbridge创建路径  
    bridge\_run->bridge\_run\_\_->ofproto\_type\_run->type\_run->xlate\_ofproto\_set
5. xbundle创建路径  
    bridge\_run->bridge\_run\_\_->ofproto\_type\_run->type\_run->xlate\_bundle\_set
6. xport创建路径  
    bridge\_run->bridge\_run\__->ofproto\_type\_run->type\_run->xlate\_ofport\_set
7. mbridge创建路径  
    bridge\_run->bridge\_reconfigure->ofproto\_create->alloc  //与ofproto相同，ofproto对象创建时会同时创建mbridge对象
8. mbundle创建路径  
    bridge\_run->bridge\_reconfigure->port\_configure->ofproto\_bundle\_register->bundle\_set //与ofbundle相同，创建ofbundle时会同时创建mbundle对象
    
一些结构定义  
ofproto\_controller（ofproto.h)

	struct ofproto_controller {
	    char *target;               /* e.g. "tcp:127.0.0.1" */
	    int max_backoff;            /* Maximum reconnection backoff, in seconds. */
	    int probe_interval;         /* Max idle time before probing, in seconds. */
	    enum ofproto_band band;     /* In-band or out-of-band? */
	    bool enable_async_msgs;     /* Initially enable asynchronous messages? */
	
	    /* OpenFlow packet-in rate-limiting. */
	    int rate_limit;             /* Max packet-in rate in packets per second. */
	    int burst_limit;            /* Limit on accumulating packet credits. */
	
	    uint8_t dscp;               /* DSCP value for controller connection. */
	};
bridge
	
	struct bridge {
	    struct hmap_node node;      /* In 'all_bridges'. */
	    char *name;                 /* User-specified arbitrary name. */
	    char *type;                 /* Datapath type. */
	    struct eth_addr ea;         /* Bridge Ethernet Address. */
	    struct eth_addr default_ea; /* Default MAC. */
	    const struct ovsrec_bridge *cfg;
	
	    /* OpenFlow switch processing. */
	    struct ofproto *ofproto;    /* OpenFlow switch. */
	
	    /* Bridge ports. */
	    struct hmap ports;          /* "struct port"s indexed by name. */
	    struct hmap ifaces;         /* "struct iface"s indexed by ofp_port. */
	    struct hmap iface_by_name;  /* "struct iface"s indexed by name. */
	
	    /* Port mirroring. */
	    struct hmap mirrors;        /* "struct mirror" indexed by UUID. */
	
	    /* Auto Attach */
	    struct hmap mappings;       /* "struct" indexed by UUID */
	
	    /* Used during reconfiguration. */
	    struct shash wanted_ports;
	
	    /* Synthetic local port if necessary. */
	    struct ovsrec_port synth_local_port;
	    struct ovsrec_interface synth_local_iface;
	    struct ovsrec_interface *synth_local_ifacep;
	};
connmgr

	/* Connection manager for an OpenFlow switch. */
	struct connmgr {
	    struct ofproto *ofproto;
	    char *name;
	    char *local_port_name;
	
	    /* OpenFlow connections. */
	    struct hmap controllers;     /* All OFCONN_PRIMARY controllers. */
	    struct ovs_list all_conns;   /* All controllers.  All modifications are
	                                    protected by ofproto_mutex, so that any
	                                    traversals from other threads can be made
	                                    safe by holding the ofproto_mutex. */
	    uint64_t master_election_id; /* monotonically increasing sequence number
	                                  * for master election */
	    bool master_election_id_defined;
	
	    /* OpenFlow listeners. */
	    struct hmap services;       /* Contains "struct ofservice"s. */
	    struct pvconn **snoops;
	    size_t n_snoops;
	
	    /* Fail open. */
	    struct fail_open *fail_open;
	    enum ofproto_fail_mode fail_mode;
	
	    /* In-band control. */
	    struct in_band *in_band;
	    struct sockaddr_in *extra_in_band_remotes;
	    size_t n_extra_remotes;
	    int in_band_queue;
	
	    ATOMIC(int) want_packet_in_on_miss;   /* Sum of ofconns' values. */
	};
	
	/* A listener for incoming OpenFlow "service" connections. */
	struct ofservice {
	    struct hmap_node node;      /* In struct connmgr's "services" hmap. */
	    struct pvconn *pvconn;      /* OpenFlow connection listener. */
	
	    /* These are not used by ofservice directly.  They are settings for
	     * accepted "struct ofconn"s from the pvconn. */
	    int probe_interval;         /* Max idle time before probing, in seconds. */
	    int rate_limit;             /* Max packet-in rate in packets per second. */
	    int burst_limit;            /* Limit on accumulating packet credits. */
	    bool enable_async_msgs;     /* Initially enable async messages? */
	    uint8_t dscp;               /* DSCP Value for controller connection */
	    uint32_t allowed_versions;  /* OpenFlow protocol versions that may
	                                 * be negotiated for a session. */
	};
	
	
	
要修改的文件及函数：  
ofproto.c: static enum ofperrhandle\_openflow\_\_, 添加消息处理函数  
ofp-msg.h: enum ofpraw, enum ofptype（消息类型）

ofp-util.c: static bool ofputil\_is\_bundlable(enum ofptype type)  
rconn.c: static bool is\_admitted\_msg(const struct ofpbuf \*b)  
可以先不改 ofp-print.c: static void ofp\_to\_string\_\_(const struct ofp\_header \*oh, enum ofpraw raw, struct ds \*string, int verbosity)     
learning-switch.c: static void lswitch\_process\_packet


---
###部分函数及数据结构
消息类型解码函数 ofp-msgs.c

	enum ofperr
	ofptype_decode(enum ofptype *typep, const struct ofp_header *oh)
	{
	    enum ofperr error;
	    enum ofpraw raw;
	
	    error = ofpraw_decode(&raw, oh);
	    *typep = error ? 0 : ofptype_from_ofpraw(raw);
	    return error;
	}
	
	enum ofperr
	ofpraw_decode(enum ofpraw *raw, const struct ofp_header *oh)
	{
	    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
	    return ofpraw_pull(raw, &msg);
	}
	
	struct ofp_header {
	    uint8_t version;    /* An OpenFlow version number, e.g. OFP10_VERSION. */
	    uint8_t type;       /* One of the OFPT_ constants. */
	    ovs_be16 length;    /* Length including this ofp_header. */
	    ovs_be32 xid;       /* Transaction id associated with this packet.
	                           Replies use the same id as was in the request
	                           to facilitate pairing. */
	};
	enum ofptype
	ofptype_from_ofpraw(enum ofpraw raw)
	{
	    return raw_info_get(raw)->type;
	}
	static const struct raw_info *
	raw_info_get(enum ofpraw raw)
	{
	    ofpmsgs_init();
	    ovs_assert(raw < ARRAY_SIZE(raw_infos)); //调试信息
	    return &raw_infos[raw];
	}
	struct ofpbuf {
	    void *base;                 /* First byte of allocated space. */
	    void *data;                 /* First byte actually in use. */
	    uint32_t size;              /* Number of bytes in use. */
	    uint32_t allocated;         /* Number of bytes allocated. */
	
	    void *header;               /* OpenFlow header. */
	    void *msg;                  /* message's body */
	    struct ovs_list list_node;  /* Private list element for use by owner. */
	    enum ofpbuf_source source;  /* Source of memory allocated as 'base'. */
	};
	
###修改ovs源码
暂时是考虑将新增消息添加到v1.3中。

1. 在include/openflow/openflow-1.3.h中扩展of协议，增加新的消息类型ofp13_mymsgtype。

		struct ofp13_mymsgtype{
		    uint16_t types;
		    uint16_t lens;
		    uint8_t pad[4];
		};
		OFP_ASSERT(sizeof(struct ofp13_mymsgtype) == 8);

2. 在 lib/ofp-msg.h 更新ofpraw这个结构体（当ovs收到来自controller的消息之后就会利用ofpraw里面格式化的定义来验证消息的有效性，从而进行后续处理）和ofptype枚举体。需要注意的是对ofpraw的更改一定要遵循固定的格式。
		
		//ofpraw:
		/* OFPT 1.3+ (35): struct ofp13_mymsgtype. */
	    OFPRAW_OFPT13_MYMSGTYPE,
	    
	    //ofptype:
	    OFPTYPE_MYMSGTYPE,                  /* 新增一个消息类型 */


3. 在lib/ofp-util.h 中添加相应的数据结构代表对应的通用类型结构，因为ovs用户空间在解码相应的消息的时候需要针对具体的类型执行相应的动作，所以也要更新 ofp-actions.h
，但对于这个简单的消息类型来说这一步似乎不需要，所以我并没有做。

		struct ofputil_mymsgtype {
		    struct ofpact *ofpacts;     /* Actions. */
		    size_t ofpacts_len;         /* Size of ofpacts in bytes. */
		};
		//解码辅助函数
		enum ofperr ofputil_decode_mymsgtype(const struct ofp_header *oh);
		//解码辅助函数,其实不需要
		struct ofpbuf *ofputil_encode_mymsgtype(const struct ofp_header *oh);


		struct ofpact_mymsgtype {
		    struct ofpact ofpact;
		    uint32_t vector;
		};



4. 修改ofproto/ofproto.c中的handle\_openflow__函数，添加对新消息的判断处理分支：

		case OFPTYPE_MYMSGTYPE:
			return handle_mymsgtype(ofconn, oh);


4. 消息处理函数handle_mymsgtype: 

		static enum ofperr
		handle_mymsgtype(struct ofconn *ofconn, const struct ofp_header *oh)
		{
			//TODO
		    VLOG_INFO("========= I GOT MYMSGTYPE FROM CONTROLLER ==========");   
		    return 0;
		}

在编译的时候会报错，说未定义类型uint16_t，尝试解决：  

* 在include/openflow/openflow-1.3.h中添加#include \<stdint.h\>，但是依旧报错  
* 修改了新增消息结构中的数据类型，这样就不报错了：  
	
		struct ofp13_mymsgtype{
		    ovs_be16 types;
		    ovs_be16 lens;
		    uint8_t pad[4];
		};
		OFP_ASSERT(sizeof(struct ofp13_mymsgtype) == 8);
		
* 编译的时候，在lib/ofp-msg.h中报错，是因为定义类型名和规则不符，以及类型名之后有空格，所以这个要求还是挺严格的。  
* 报错：nicira-ext.h，但是错误行其实是注释，于是就把报错的那一块注释删掉了。

安装:

* make