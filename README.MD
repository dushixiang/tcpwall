## tcpwall 
当我们想要阻止某些TCP连接的建立，在Linux平台上有一个很好的解决方案**iptables**，但是对那些已经建立的tcp连接，iptables就不能做到随心所欲的阻断了。

我在互联网上检索的时候发现了**tcpkill**这个工具，tcpkill是一个网络分析工具集**dsniff**中的一个小工具。在Linux上可以直接通过dsniff包安装，使用方式也非常简单。

通过测试我发现tcpkill在执行命令之后并不会立刻阻断tcp连接，而是等待有数据传输时，才会阻断，因此在执行完命令之后程序并不会主动退出，而是需要通过***Ctrl+C***来退出，这对于某些想要通过程序来调用的脚本小子（例如我）来说简直是个灾难。

## 如何阻断一个已经建立的tcp连接？
阻断一个已经建立的tcp连接通常有这几种方案：
1. 服务端主动断开
2. 客户端主动断开
3. 拔掉网线（时间要超过tcp超时时间）
4. 伪造RST数据包发送给服务端和客户端让它们主动断开（tcpkill就是这么做的）

前三种局限性太大，只能用第4种了。

## 如何实现伪造RST数据报文包？

[GoPacket](https://github.com/google/gopacket) 是go基于**libpcap**构建的一个库，可以通过旁路的方式接收一份数据包的拷贝。因此我们可以很方便捕获到正在通信的tcp数据报文。通过数据报文，我们可以获取到通信双方的MAC地址，IP和端口号，以及ACK号等，这些都是伪造数据包必不可少的。

在学习了**tcpkill**的源码之后，我使用go开发了一个增强版的**tcpwall**，**tcpwall**不仅可以实现和**tcpkill**同样的基于ip或端口监听到指定数据报文之后伪造RST数据报文来阻断tcp连接，也可以通过源ip源端口，目的ip目的端口来主动发送SYN数据报文包来诱导那些没有数据的tcp连接发送ACK数据报文包以获取源MAC、目的MAC和ACK号，并且可以通过指定参数让程序等待一段时间后主动退出。

## 如何使用

阻断指定IP和端口的TCP连接（不关心是源或者目的）
```
tcpwall -i {interface} -host {host} -port {port}
```

阻断指定源IP和源端口的TCP连接
```
tcpwall -i {interface} -shost {src_host} -sport {src_port}
```

阻断指定目的IP和目的端口的TCP连接
```
tcpwall -i {interface} -dhost {dst_host} -dport {dst_port}
```

阻断指定源IP、源端口、目的IP、目的端口的TCP连接（会主动向双方发送SYN数据报文包）
```
tcpwall -i {interface} -shost {src_host} -sport {src_port} -dhost {dst_host} -dport {dst_port}
```

## 其他

 - -timeout 时间（秒）指定等待多久之后退出程序