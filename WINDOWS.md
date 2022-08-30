## 原理
tun设备是指运行在ip层的虚拟网卡，如果我们能在windows上建立一个tun设备，
再加上策略路由将所有的在国外的ip路由到这个tun设备上，最终我们就可以实现全局代理的目标。
### Tun
windows上的tun有一个专门的库叫wintun，这个库已经被port到rust上了，因此我们可以直接使用。
但是这里还有另外一个问题需要我们来处理，那就是ip协议，这可以利用smoltcp这个rust库来进行处理。
当tun设备收到ip包之后由smoltcp来处理，我们将收到的数据通过trojan协议发送给trojan服务器。
这部分功能由于trojan wintun子命令来完成
### DNS
由于windows上缺少类似dnsmasq的DNS服务，因此我们需要自己提供一个类似的，这部分功能由trojan dns子命令完成

## 使用
以管理员权限启动wintun，然后再启动dns即可