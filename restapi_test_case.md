####RESTAPI测试样例
#####使用
首先，你需要拥有openvswitch-2.5.2-z.tar.gz，ryu-z.tar.gz和ruletables-service-z.tar.gz（-z表示这是修改过的源码，以免混淆） 

0. 安装mininet。
 

1. 解压openvswitch-2.5.2-z.tar.gz，进入其目录下：



2. 进入ryu的目录下：



3. 进入ruletables的目录下：




#####说明
match域的匹配条件有：  
table\_name，command，priority，chain\_name，action，index，source\_ip，dest\_ip，source\_ip\_mask，dest\_ip\_mask，proto，source\_port1，source\_port2，dest\_port1，dest\_port2。  

RYU运行:  
$ ryu-manager /ryu/app/ofctl\_rest.py /ryu/app/my\_simple\_switch\_13.py

使用Firefox的插件HttpRequester或者Chrome插件POSTMAN进行测试。
#####样例
* 清空 iptables -t filter -F

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":4,
		    "table_name":1
		    }
		}
* iptables -t filter -A INPUT -j ACCEPT -s 192.168.1.0/24

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":1,
		    "table_name":1,
		    "chain_name":2,
		    "action":1,
		    "source_ip":"192.168.1.0",
		    "source_ip_mask":"255.255.255.0"
			}
		}
* iptables -t filter -A OUTPUT -j ACCEPT -d 192.168.10.1 -p tcp --dport 80

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":1,
		    "table_name":1,
		    "chain_name":3,
		    "action":1,
		    "dest_ip":"192.168.10.1",
		    "proto": 1,
		    "dest_port1":80
			}
		}
* iptables -t filter -D INPUT 2
		
		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":3,
		    "table_name":1,
		    "chain_name":2,
		    "index":2
			}
		}
* iptables -t filter -A INPUT -j REJECT -s 192.168.2.0/24 -p udp --sport 100:200

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":1,
		    "table_name":1,
		    "chain_name":2,
		    "action":2,
		    "source_ip":"192.168.2.0",
		    "source_ip_mask":"255.255.255.0",
		    "proto": 2,
		    "source_port1":100,
		    "source_port2":200
			}
		}
* iptables -t filter -R INPUT 3 -j REJECT -s 192.168.2.0/24 -d 192.168.3.0/24 

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":2,
		    "table_name":1,
		    "chain_name":2,
		    "action":2,
		    "index":3,
		    "source_ip":"192.168.2.0",
		    "source_ip_mask":"255.255.255.0",
		    "dest_ip":"192.168.3.0",
		    "dest_ip_mask":"255.255.255.0"
			}
		}
* iptable -t filter -P FORWARD DROP

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":0,
		    "table_name":1,
		    "chain_name":4,
		    "action":3
			}
		}
		
* 向ryu返回当前ruletables里的所有规则

		{
		"dip":"127.0.0.1",
		"dport":6666,
		"match":{
		    "command":5
			}
		}
