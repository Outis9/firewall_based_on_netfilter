# security_tech_final_project
## 题目要求:
基于Netfilter或者Libnetfilter_queue开发一个静态包过滤防火墙，具体要求：
（1）对符合指定的网络协议（TCP或UDP）、源IP地址、目的IP地址、源端口和目的端口的报文进行阻止。
（2）在命令行参数指定过滤规则，例如指定需要阻止的网络协议、源IP地址、目的IP地址、源端口和目的端口等。

## 目前实现
1. 对符合指定的TCP/UDP/ICMP协议进行过滤
2. 对相应ip地址，端口进行过滤
3. 可以对多个ip地址和多个端口进行过滤
4. 完善了flush函数，可以清空存在的所有规则


## 需要开发
1. 分清源端口，目的端口，源地址，目的地址   done
2. 命令行工具开发                         done

## BUG
1. ip / port 输入合法性问题               done
2. ban list 中重复出现问题
3. 输入两遍指令，解除封禁效果问题          done

~~~shell
sudo ./dropit -s 47.100.167.12 -j drop
sudo ./dropit -d 8.8.8.8 -j drop
sudo ./dropit -p tcp -j drop
sudo ./dropit -p udp -j drop
sudo ./dropit -p icmp -j drop
sudo ./dropit -z 53 -j drop
sudo ./dropit -x 53 -j drop
sudo ./dropit -h
sudo ./dropit -f
~~~





