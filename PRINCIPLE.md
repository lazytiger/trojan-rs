# 透明代理的基本原理

所谓透明代理其实就是不需要让客户端做任何事情，操作系统直接将所有的请求按规则转发到代理服务器的实现方式。
本文仅就linux下利用iptables来进行透明代理实现的原理进行描述。下文中SERVER指trojan server模式，PROXY指trojan proxy模式

## 请求转发

实现透明代理的第一步是如何在操作系统层面有选择的将一部分请求转交给PROXY，然后由PROXY送到SERVER。这一点在linux系统上一般
都是用iptables来实现的。具体如何实现分为udp和tcp两个协议各有不同，至于有选择这个一般利用ipset来实现。
ipset是linux下提供的一个ip集合，在iptables里可以使用这个定义好的集合来进行转发。

### TCP

tcp的请求转发一般有两种方式，一种是通过nat的redirect来实现
> iptables -t nat -A PREROUTING -p tcp -m set ! --match-set chslist dst -j REDIRECT --to-ports 1080

这个命令就实现了将不在chslist这个ipset里的目标地址请求都转发到1080这个端口上的目的。
还有一种方式是本项目用于实现的tproxy策略,tproxy是transparent proxy的简写，这个策略的使用mangle来完成，具体如下：
> iptables -t mangle -A PREROUTING -p tcp -m set ! --match-set chslist dst -j TPROXY --on-port 1080 --on-ip 127.0.0.1
> --tproxy-mark 1

这个命令就实现了跟上面redirect类型的功能，将请求转发到127.0.01的1080端口上

当请求转发之后的事情就比较简单了，我们可以的PROXY正常listen在1080端口上，就会accept到连接请求，
然后我们取到这个连接的目标地址（redirect可以用getsockopt中的SO_ORIGINAL_DST来获取， tproxy可以直接使用getsockname).
再然后我们建立一个到SERVER的连接，并告诉SERVER将如下数据流转发给刚才取到的目标服务器，然后就开始充当一个中间转发的角色就可以了。

### UDP

udp的请求转发目前似乎只有一种方式，就是tproxy。
> iptables -t mangle -A PREROUTING -p udp -m set ! --match-set chslist dst -j TPROXY --on-port 1080 --on-ip 127.0.0.1
> --tproxy-mark 1

上面这条命令与tcp唯一的不同就是协议换成了udp，作用也是一样的，即将udp包转发给1080端口。同样的，PROXY在127.0.0.1的1080端口
监听一个udp server，当有请求来的时候，我们可以取到udp的目标地址，具体参考sys::recv_from_with_destination.
再然后跟tcp一样，我们将请求通过PROXY送到SERVER，然后由SERVER将请求转发给目标，SERVER在取到响应之后返回PROXY。PROXY必须将这个包
以目标地址的名义发出去，否则udp接收端可能会拒绝，这一点跟tcp不一样，因为tcp是基于连接的，连接建立之后大家不再管地址。这个时候tproxy的
作用就体现了，它可以让我们的bind到任意地址上去，于是我们bind为目标地址，然后通过它再send_to给源地址。

## 透明代理TPROXY

TPROXY一般是通过IP_TRANSPARENT选项来实现，它有两个作用

* 可以使得socket bind到任意地址
* 可以使得socket接收到来自iptables TPROXY转发的请求

所以，我们得给udp socket和tcp listener都设置这个选项就可以拦截到请求，这个是在socket层面的，配合上面的iptables规则来使用.
关于TPROXY的更详细的解释大家可以参考[这篇文章](https://powerdns.org/tproxydoc/tproxy.md.html)

## 策略路由

当linux路由的时候，它仅会把它认为是本地请求的包路由到本地，其他的包要么丢弃，要求从网络接口上送出去。那我们怎么才能保证
linux将我们上面通过TPROXY转发的请求认为是本地请求给到本地服务，而不是路由出去呢？这个时候就是策略路由出场的时候了
> ip rule add fwmark 1 lookup 100<br>
> ip route add local 0.0.0.0/0 dev lo table 100<br>

* 第一条告诉linux，所有mark为1的数据包请路由给table 100；
* 第二条是table 100的路由规则，将0.0.0.0/0这个网段的所有包（也即真的是所有包）都当作本地包路由给lo设备，也即127.0.0.1

好了，这个时候我们看到了fwmark，这是一个可通过SO_MARK这个选项来给socket进行设置的参数，它其实是可以给ip包打个标记以备后面使用。
我们再来回顾一下上面的iptables规则，*--tproxy-mark 1* 我们并没有说明它的作用，其实它就是让符合这个规则的数据包从iptables出去的时候
mark为1，这与我们上面的策略路由里用到的mark是一样的。其实这两个数保持一致就好了，不一定非得用1.

## 本地代理

上面的路由规则里大家都看到了用的是PREROUTING这个规则链，这个规则链是用于路由外面进来的包的，自己本地产生
的包实现上是通过OUTPUT链出去的，而OUTPUT已经过了PREROUTING这个阶段了，那是不是就没办法在本机上实现透明代理了呢？其实不是的，利用mark
还可以通过下面的规则来实现
> iptables -t mangle -A OUTPUT -m mark --mark 0xff -j RETURN<br>
> iptables -t mangle -A OUTPUT -p tcp -m tcp --dport 443 -j MARK --set-xmark 1

上面这条规则是说，从OUTPUT出去的tcp包，凡是目标端口是443的,将它mark为1，而打一个包被重新mark的时候就会触发重路由，这个时候
它又会重新进入到PREROUTING的阶段，于是我们就又可以拦截它了。~~~但是需要注意的是，这个规则要生效我们就必须要加上面那条规则，
那个规则的意思是，如果当前包被标记为0xff，那么我们就不要再管它了，让它直接出去就行了。为什么需要这条呢？原因是我们所有从本地发
出去的请求都会到OUTPUT，也即是说我们发给代理服务器的请求也会走到这里，但是我们显然不希望这些包再回到自己从而形成死循环，所以这条
规则就显得尤其重要了。那么要实现这一点，我们就必须在PROXY端上将所有的socket的SO_MARK参数设置为0xff，以达到让它们直接路由出去而
不是回到自己。注意这个参数在我们的程序里可以通过-m参数来指定，默认是255(0xff)，大家可以将它修改为任意自己想要的值。~~~
事实上这里的描述之前有些问题，
因为我们一般会把到目标代理服务器的请求提前放过，因此mark并不是必须的，除非是一个动态的代理服务器地址。

## 系统参数

其实到这里的时候原理性的东西基本上都说完了，唯一剩下的就是一些sysctl的参数了
> net.ipv4.ip_forward=1<br>
> net.ipv4.conf.all.route_localnet = 1<br>
> net.ipv4.conf.eth0.rp_filter = 0<br>

第一个是告诉linux它自己要有路由功能，于是PREROUTING会生效，
第二个是告诉linux，localhost也是需要路由的
第三个是告诉linux，不要检查源地址，否则在路由出去的时候会被linux丢弃，如果是本地透明代理这一条则不需要

## 趟坑总结

* 大家在写iptables的时候特别需要注意的是，到代理服务器的ip一定要排除到PREROUTING里，否则又会形成路由回环。
* ~~rustls与mio共同使用时，记得一定要用level而不能用edge，猜测可能是rustls因为某些原因并没有将socket读到WouldBlock~~
  mio和rustls升级之后这个问题似乎已经修复了
* 服务器端最好将所有墙内ip的udp回包给drop掉，因为可能某些软件的打洞机制会错将代理的ip给暴露出去，从而将udp从代理回来。
* 在https连接没建立好的时候，write_tls是不会将用户数据写给服务器的，因此上需要在每次从服务器读到数据的时候做一下flush操作，看看能不能把数据写回服务器