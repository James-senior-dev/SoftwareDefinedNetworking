from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections, quietRun
from mininet.log import setLogLevel, info, info, error, debug, output, warn
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.link import TCLink, Intf
from mininet.cli import CLI
from mininet.node import Node, Switch
import time, re, os

class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(Router, self).terminate()

def checkIntf(intf):
    "Make sure intf exists and is not configured."
    config = quietRun('ifconfig %s 2>/dev/null' % intf, shell=True)
    if not config:
        error('Error:', intf, 'does not exist!\n')
        exit(1)
    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', config)
    if ips:
        error('Error:', intf, 'has an IP address,'
              'and is probably in use!\n')
        exit(1)

class Netzwerk(Topo):
    def build(self, **_opts):

        defaultIP = '192.168.%s.1/24'

        routers = []

        for r in range(4):
            router = self.addNode('r%s' % (r+1),
                                  cls=Router, ip=defaultIP % (r+1),
                                  mac='00:00:00:00:00:0%s' % (r+1)
                                  )

            routers.append(router)

            switch = self.addSwitch('s%s' % (r+1))

            self.addLink(switch, router)

            for h in range(10):
                name = ((r)*10)+(h+1)
                host = self.addHost(name='h%s' % (name),
                                    ip='0.0.0.0',
                                    defaultRoute='via 192.168.%s.1' % (r+1),
                                    mac='00:00:00:00:0%s:%s0' % (r+1, h)
                                    )
                self.addLink(host, switch)

        self.addLink(routers[0],
                     routers[1],
                     intfName1='r1-eth2',
                     intfName2='r2-eth2',
                     params1={'ip': '10.100.12.1/24'},
                     params2={'ip': '10.100.12.2/24'},
                     bw=20
                     )
        self.addLink(routers[2],
                     routers[3],
                     intfName1='r3-eth2',
                     intfName2='r4-eth2',
                     params1={'ip': '10.100.34.3/24'},
                     params2={'ip': '10.100.34.4/24'},
                     bw=20
                     )
        self.addLink(routers[0],
                     routers[2],
                     intfName1='r1-eth3',
                     intfName2='r3-eth3',
                     params1={'ip': '10.100.13.1/24'},
                     params2={'ip': '10.100.13.3/24'},
                     bw=20
                     )
        self.addLink(routers[0],
                     routers[3],
                     intfName1='r1-eth4',
                     intfName2='r4-eth3',
                     params1={'ip': '10.100.14.1/24'},
                     params2={'ip': '10.100.14.4/24'},
                     bw=20
                     )
        self.addLink(routers[1],
                     routers[2],
                     intfName1='r2-eth3',
                     intfName2='r3-eth4',
                     params1={'ip': '10.100.23.2/24'},
                     params2={'ip': '10.100.23.3/24'},
                     bw=20
                     )
        self.addLink(routers[1],
                     routers[3],
                     intfName1='r2-eth4',
                     intfName2='r4-eth4',
                     params1={'ip': '10.100.24.2/24'},
                     params2={'ip': '10.100.24.4/24'},
                     bw=20
                     )

def Main():
    topo = Netzwerk()
    
    os.system("sudo ovs-vsctl add-br s1")
    os.system("sudo ovs-vsctl add-br s2")
    os.system("sudo ovs-vsctl add-br s3")
    os.system("sudo ovs-vsctl add-br s4")
    os.system("sudo ip addr add 192.168.1.20/24 dev s1")
    os.system("sudo ip link set s1 up")
    os.system("sudo ip addr add 192.168.2.20/24 dev s2")
    os.system("sudo ip link set s2 up")
    os.system("sudo ip addr add 192.168.3.20/24 dev s3")
    os.system("sudo ip link set s3 up")
    os.system("sudo ip addr add 192.168.4.20/24 dev s4")
    os.system("sudo ip link set s4 up")

    os.system("sudo ip route add default via 192.168.1.1")

    c0 = RemoteController('c0', controller=RemoteController,
                          ip="192.168.1.20", port=6653)

    net = Mininet(topo=topo, controller=c0,
                  link=TCLink, switch=OVSSwitch, waitConnected=True)

    info(net['r1'].cmd(
        "ip tunnel add gre12 mode gre local 10.100.12.1 remote 10.100.12.2 ttl 255"))
    info(net['r1'].cmd("ip link set gre12 up"))
    info(net['r1'].cmd("ip addr add 10.10.12.1/24 dev gre12"))

    info(net['r1'].cmd(
        "ip tunnel add gre13 mode gre local 10.100.13.1 remote 10.100.13.3 ttl 255"))
    info(net['r1'].cmd("ip link set gre13 up"))
    info(net['r1'].cmd("ip addr add 10.10.13.1/24 dev gre13"))

    info(net['r1'].cmd(
        "ip tunnel add gre14 mode gre local 10.100.14.1 remote 10.100.14.4 ttl 255"))
    info(net['r1'].cmd("ip link set gre14 up"))
    info(net['r1'].cmd("ip addr add 10.10.14.1/24 dev gre14"))

    info(net['r2'].cmd(
        "ip tunnel add gre21 mode gre local 10.100.12.2 remote 10.100.12.1 ttl 255"))
    info(net['r2'].cmd("ip link set gre21 up"))
    info(net['r2'].cmd("ip addr add 10.10.12.2/24 dev gre21"))

    info(net['r2'].cmd(
        "ip tunnel add gre23 mode gre local 10.100.23.2 remote 10.100.23.3 ttl 255"))
    info(net['r2'].cmd("ip link set gre23 up"))
    info(net['r2'].cmd("ip addr add 10.10.23.2/24 dev gre23"))

    info(net['r2'].cmd(
        "ip tunnel add gre24 mode gre local 10.100.24.2 remote 10.100.24.4 ttl 255"))
    info(net['r2'].cmd("ip link set gre24 up"))
    info(net['r2'].cmd("ip addr add 10.10.24.2/24 dev gre24"))

    info(net['r3'].cmd(
        "ip tunnel add gre31 mode gre local 10.100.13.3 remote 10.100.13.1 ttl 255"))
    info(net['r3'].cmd("ip link set gre31 up"))
    info(net['r3'].cmd("ip addr add 10.10.13.3/24 dev gre31"))

    info(net['r3'].cmd(
        "ip tunnel add gre32 mode gre local 10.100.23.3 remote 10.100.23.2 ttl 255"))
    info(net['r3'].cmd("ip link set gre32 up"))
    info(net['r3'].cmd("ip addr add 10.10.23.3/24 dev gre32"))

    info(net['r3'].cmd(
        "ip tunnel add gre34 mode gre local 10.100.34.3 remote 10.100.34.4 ttl 255"))
    info(net['r3'].cmd("ip link set gre34 up"))
    info(net['r3'].cmd("ip addr add 10.10.34.3/24 dev gre34"))

    info(net['r4'].cmd(
        "ip tunnel add gre41 mode gre local 10.100.14.4 remote 10.100.14.1 ttl 255"))
    info(net['r4'].cmd("ip link set gre41 up"))
    info(net['r4'].cmd("ip addr add 10.10.14.4/24 dev gre41"))

    info(net['r4'].cmd(
        "ip tunnel add gre42 mode gre local 10.100.24.4 remote 10.100.24.2 ttl 255"))
    info(net['r4'].cmd("ip link set gre42 up"))
    info(net['r4'].cmd("ip addr add 10.10.24.4/24 dev gre42"))

    info(net['r4'].cmd(
        "ip tunnel add gre43 mode gre local 10.100.34.4 remote 10.100.34.3 ttl 255"))
    info(net['r4'].cmd("ip link set gre43 up"))
    info(net['r4'].cmd("ip addr add 10.10.34.4/24 dev gre43"))

    info(net['r1'].cmd("ip route add 192.168.2.0/24 via 10.10.12.2 dev gre12"))
    info(net['r2'].cmd("ip route add 192.168.1.0/24 via 10.10.12.1 dev gre21"))

    info(net['r1'].cmd("ip route add 192.168.3.0/24 via 10.10.13.1 dev gre13"))
    info(net['r3'].cmd("ip route add 192.168.1.0/24 via 10.10.13.3 dev gre31"))

    info(net['r1'].cmd("ip route add 192.168.4.0/24 via 10.10.14.1 dev gre14"))
    info(net['r4'].cmd("ip route add 192.168.1.0/24 via 10.10.14.4 dev gre41"))

    info(net['r2'].cmd("ip route add 192.168.3.0/24 via 10.10.23.2 dev gre23"))
    info(net['r3'].cmd("ip route add 192.168.2.0/24 via 10.10.23.3 dev gre32"))

    info(net['r2'].cmd("ip route add 192.168.4.0/24 via 10.10.24.2 dev gre24"))
    info(net['r4'].cmd("ip route add 192.168.2.0/24 via 10.10.24.4 dev gre42"))

    info(net['r3'].cmd("ip route add 192.168.4.0/24 via 10.10.34.3 dev gre34"))
    info(net['r4'].cmd("ip route add 192.168.3.0/24 via 10.10.34.4 dev gre43"))

    key12 = "0xf1e125c62a8f68169ff9d0375d901\
    7b76c700354e3060ef78a61e43547babd0d"
    key21 = "0xc9d786b186394addc49c08fc551cd\
    5cf580f7cd600da9ed5c47d1ab7b7e510ec"
    spi12 = "0x1cac64a1"
    spi21 = "0xd03e561e"

    info(net['r1'].cmd("ip xfrm state add src 10.100.12.1 dst 10.100.12.2 proto esp spi " +
                       spi12 + " enc 'cbc(aes)' " + key12 + " mode transport"))
    info(net['r1'].cmd("ip xfrm state add src 10.100.12.2 dst 10.100.12.1 proto esp spi " +
                       spi21 + " enc 'cbc(aes)' " + key21 + " mode transport"))

    info(net['r2'].cmd("ip xfrm state add src 10.100.12.1 dst 10.100.12.2 proto esp spi " +
                       spi12 + " enc 'cbc(aes)' " + key12 + " mode transport"))
    info(net['r2'].cmd("ip xfrm state add src 10.100.12.2 dst 10.100.12.1 proto esp spi " +
                       spi21 + " enc 'cbc(aes)' " + key21 + " mode transport"))

    info(net['r1'].cmd(
        "ip xfrm policy add dir out src 10.100.12.1 dst 10.100.12.2 tmpl proto esp mode transport"))
    info(net['r1'].cmd(
        "ip xfrm policy add dir in src 10.100.12.2 dst 10.100.12.1 tmpl proto esp mode transport"))

    info(net['r2'].cmd(
        "ip xfrm policy add dir out src 10.100.12.2 dst 10.100.12.1 tmpl proto esp mode transport"))
    info(net['r2'].cmd(
        "ip xfrm policy add dir in src 10.100.12.1 dst 10.100.12.2 tmpl proto esp mode transport"))

    key13 = "0x66bb7cc6569bd163f9bc08b18e2c\
    713d5bb9e907e19ca5fec3e912ded56d4f3f"
    key31 = "0x7859f3b5ec4fc371d0f39ae07c30\
    36e8fd604ba1da981ed6f369e8eb09883725"
    spi13 = "0x689ba869"
    spi31 = "0x0f054cf0"

    info(net['r1'].cmd("ip xfrm state add src 10.100.13.1 dst 10.100.13.3 proto esp spi " +
                       spi13 + " enc 'cbc(aes)' " + key13 + " mode transport"))
    info(net['r1'].cmd("ip xfrm state add src 10.100.13.3 dst 10.100.13.1 proto esp spi " +
                       spi31 + " enc 'cbc(aes)' " + key31 + " mode transport"))

    info(net['r3'].cmd("ip xfrm state add src 10.100.13.1 dst 10.100.13.3 proto esp spi " +
                       spi13 + " enc 'cbc(aes)' " + key13 + " mode transport"))
    info(net['r3'].cmd("ip xfrm state add src 10.100.13.3 dst 10.100.13.1 proto esp spi " +
                       spi31 + " enc 'cbc(aes)' " + key31 + " mode transport"))

    info(net['r1'].cmd(
        "ip xfrm policy add dir out src 10.100.13.1 dst 10.100.13.3 tmpl proto esp mode transport"))
    info(net['r1'].cmd(
        "ip xfrm policy add dir in src 10.100.13.3 dst 10.100.13.1 tmpl proto esp mode transport"))

    info(net['r3'].cmd(
        "ip xfrm policy add dir out src 10.100.13.3 dst 10.100.13.1 tmpl proto esp mode transport"))
    info(net['r3'].cmd(
        "ip xfrm policy add dir in src 10.100.13.1 dst 10.100.13.3 tmpl proto esp mode transport"))

    key14 = "0x8527ef297dc35bed418d635ef15\
    e219feaf5f5597699b6271534697bfdf940c9"
    key41 = "0x69091e7f7c1c162c7c6b44fb8e3\
    89e113eb77746c1d6a2d73074e9609a991179"
    spi14 = "0x19de2473"
    spi41 = "0x65cb9866"

    info(net['r1'].cmd("ip xfrm state add src 10.100.14.1 dst 10.100.14.4 proto esp spi " +
                       spi14 + " enc 'cbc(aes)' " + key14 + " mode transport"))
    info(net['r1'].cmd("ip xfrm state add src 10.100.14.4 dst 10.100.14.1 proto esp spi " +
                       spi41 + " enc 'cbc(aes)' " + key41 + " mode transport"))

    info(net['r4'].cmd("ip xfrm state add src 10.100.14.1 dst 10.100.14.4 proto esp spi " +
                       spi14 + " enc 'cbc(aes)' " + key14 + " mode transport"))
    info(net['r4'].cmd("ip xfrm state add src 10.100.14.4 dst 10.100.14.1 proto esp spi " +
                       spi41 + " enc 'cbc(aes)' " + key41 + " mode transport"))

    info(net['r1'].cmd(
        "ip xfrm policy add dir out src 10.100.14.1 dst 10.100.14.4 tmpl proto esp mode transport"))
    info(net['r1'].cmd(
        "ip xfrm policy add dir in src 10.100.14.4 dst 10.100.14.1 tmpl proto esp mode transport"))

    info(net['r4'].cmd(
        "ip xfrm policy add dir out src 10.100.14.4 dst 10.100.14.1 tmpl proto esp mode transport"))
    info(net['r4'].cmd(
        "ip xfrm policy add dir in src 10.100.14.1 dst 10.100.14.4 tmpl proto esp mode transport"))

    key23 = "0xe6709e851cc4f247729bb592147\
    663ab4e4fe26cced514120e92aaf3034061f8"
    key32 = "0xc765d3e9382d7012963fc2c0d66\
    e20724ba2de74928e6c9f08c0250d6ac5f823"
    spi23 = "0x18d7e3e4"
    spi32 = "0x93e5489f"

    info(net['r2'].cmd("ip xfrm state add src 10.100.23.2 dst 10.100.23.3 proto esp spi " +
                       spi23 + " enc 'cbc(aes)' " + key23 + " mode transport"))
    info(net['r2'].cmd("ip xfrm state add src 10.100.23.3 dst 10.100.23.2 proto esp spi " +
                       spi32 + " enc 'cbc(aes)' " + key32 + " mode transport"))

    info(net['r3'].cmd("ip xfrm state add src 10.100.23.2 dst 10.100.23.3 proto esp spi " +
                       spi23 + " enc 'cbc(aes)' " + key23 + " mode transport"))
    info(net['r3'].cmd("ip xfrm state add src 10.100.23.3 dst 10.100.23.2 proto esp spi " +
                       spi32 + " enc 'cbc(aes)' " + key32 + " mode transport"))

    info(net['r2'].cmd(
        "ip xfrm policy add dir out src 10.100.23.2 dst 10.100.23.3 tmpl proto esp mode transport"))
    info(net['r2'].cmd(
        "ip xfrm policy add dir in src 10.100.23.3 dst 10.100.23.2 tmpl proto esp mode transport"))

    info(net['r3'].cmd(
        "ip xfrm policy add dir out src 10.100.23.3 dst 10.100.23.2 tmpl proto esp mode transport"))
    info(net['r3'].cmd(
        "ip xfrm policy add dir in src 10.100.23.2 dst 10.100.23.3 tmpl proto esp mode transport"))

    key24 = "0xd2851d694a952d4e14b1eda4ee20\
    04e94f601e7422e47c1872ad6d333b7e1d37"
    key42 = "0xcb7698938b9393686afde8b29e2c\
    1e620b99f1fe2435c24709a9ffccfea050f6"
    spi24 = "0x7d99d7e8"
    spi42 = "0x508ef1f2"

    info(net['r2'].cmd("ip xfrm state add src 10.100.24.2 dst 10.100.24.4 proto esp spi " +
                       spi24 + " enc 'cbc(aes)' " + key24 + " mode transport"))
    info(net['r2'].cmd("ip xfrm state add src 10.100.24.4 dst 10.100.24.2 proto esp spi " +
                       spi42 + " enc 'cbc(aes)' " + key42 + " mode transport"))

    info(net['r4'].cmd("ip xfrm state add src 10.100.24.2 dst 10.100.24.4 proto esp spi " +
                       spi24 + " enc 'cbc(aes)' " + key24 + " mode transport"))
    info(net['r4'].cmd("ip xfrm state add src 10.100.24.4 dst 10.100.24.2 proto esp spi " +
                       spi42 + " enc 'cbc(aes)' " + key42 + " mode transport"))

    info(net['r2'].cmd(
        "ip xfrm policy add dir out src 10.100.24.2 dst 10.100.24.4 tmpl proto esp mode transport"))
    info(net['r2'].cmd(
        "ip xfrm policy add dir in src 10.100.24.4 dst 10.100.24.2 tmpl proto esp mode transport"))

    info(net['r4'].cmd(
        "ip xfrm policy add dir out src 10.100.24.4 dst 10.100.24.2 tmpl proto esp mode transport"))
    info(net['r4'].cmd(
        "ip xfrm policy add dir in src 10.100.24.2 dst 10.100.24.4 tmpl proto esp mode transport"))

    key34 = "0xa5036e96c1ee40de3cb7ebc6a455f\
    a816053b6106a352634da87e67b1137c058"
    key43 = "0x4e2ea7cb3ec6d11704d2a85b7f7db\
    3518ddcf970ff54502ff8ea6be653c6b456"
    spi34 = "0x7302a4a9"
    spi43 = "0xc70a7221"

    info(net['r3'].cmd("ip xfrm state add src 10.100.34.3 dst 10.100.34.4 proto esp spi " +
                       spi34 + " enc 'cbc(aes)' " + key34 + " mode transport"))
    info(net['r3'].cmd("ip xfrm state add src 10.100.34.4 dst 10.100.34.3 proto esp spi " +
                       spi43 + " enc 'cbc(aes)' " + key43 + " mode transport"))

    info(net['r4'].cmd("ip xfrm state add src 10.100.34.3 dst 10.100.34.4 proto esp spi " +
                       spi34 + " enc 'cbc(aes)' " + key34 + " mode transport"))
    info(net['r4'].cmd("ip xfrm state add src 10.100.34.4 dst 10.100.34.3 proto esp spi " +
                       spi43 + " enc 'cbc(aes)' " + key43 + " mode transport"))

    info(net['r3'].cmd(
        "ip xfrm policy add dir out src 10.100.34.3 dst 10.100.34.4 tmpl proto esp mode transport"))
    info(net['r3'].cmd(
        "ip xfrm policy add dir in src 10.100.34.4 dst 10.100.34.3 tmpl proto esp mode transport"))

    info(net['r4'].cmd(
        "ip xfrm policy add dir out src 10.100.34.4 dst 10.100.34.3 tmpl proto esp mode transport"))
    info(net['r4'].cmd(
        "ip xfrm policy add dir in src 10.100.34.3 dst 10.100.34.4 tmpl proto esp mode transport"))

    info('*** Routing Table on Router:\n')
    info(net['r1'].cmd('route'))
    info(net['r2'].cmd('route'))
    info(net['r3'].cmd('route'))
    info(net['r4'].cmd('route'))

    checkIntf('enp0s9')
    s1 = net.getNodeByName('s1')
    _intf = Intf('enp0s9', node=s1)

    checkIntf('enp0s10')
    s2 = net.getNodeByName('s2')
    _intf = Intf('enp0s10', node=s2)

    net.start()

    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")

    r1 = net.getNodeByName('r1')
    Intf('enp0s16', node=r1)
    info(net['r1'].cmd("dhclient enp0s16"))
    info(net['r1'].cmd("sudo iptables -t nat -A POSTROUTING -o enp0s16 -j MASQUERADE"))

    r2 = net.getNodeByName('r2')
    Intf('enp0s17', node=r2)
    info(net['r2'].cmd("dhclient enp0s17"))
    info(net['r2'].cmd("sudo iptables -t nat -A POSTROUTING -o enp0s17 -j MASQUERADE"))

    r3 = net.getNodeByName('r3')
    Intf('enp0s18', node=r3)
    info(net['r3'].cmd("dhclient enp0s18"))
    info(net['r3'].cmd("sudo iptables -t nat -A POSTROUTING -o enp0s18 -j MASQUERADE"))

    r4 = net.getNodeByName('r4')
    Intf('enp0s19', node=r4)
    info(net['r4'].cmd("dhclient enp0s19"))
    info(net['r4'].cmd("sudo iptables -t nat -A POSTROUTING -o enp0s19 -j MASQUERADE"))

    os.system("service isc-dhcp-server restart")

    for i in range(40):
        host = net.getNodeByName('h%s' % (i+1))
        host.cmd("dhclient h%s-eth0" % (i+1))

    os.system("sudo ovs-ofctl add-flow s1 priority=1000,actions=set_queue:0,normal")
    os.system("sudo ovs-ofctl add-flow s2 priority=1000,actions=set_queue:0,normal")
    os.system("sudo ovs-ofctl add-flow s3 priority=1000,actions=set_queue:0,normal")
    os.system("sudo ovs-ofctl add-flow s4 priority=1000,actions=set_queue:0,normal")
    
    os.system("sudo ovs-ofctl add-flow s1 priority=65535,udp,nw_src=192.168.0.0/16,nw_dst=192.168.0.0/16,actions=set_queue:1,normal")
    os.system("sudo ovs-ofctl add-flow s2 priority=65535,udp,nw_src=192.168.0.0/16,nw_dst=192.168.0.0/16,actions=set_queue:1,normal")
    os.system("sudo ovs-ofctl add-flow s3 priority=65535,udp,nw_src=192.168.0.0/16,nw_dst=192.168.0.0/16,actions=set_queue:1,normal")
    os.system("sudo ovs-ofctl add-flow s4 priority=65535,udp,nw_src=192.168.0.0/16,nw_dst=192.168.0.0/16,actions=set_queue:1,normal")

    CLI(net)

    info(net['r1'].cmd("ip link set enp0s16 netns 1"))
    info(net['r2'].cmd("ip link set enp0s17 netns 1"))
    info(net['r3'].cmd("ip link set enp0s18 netns 1"))
    info(net['r4'].cmd("ip link set enp0s19 netns 1"))

    os.system("sudo ip addr del 192.168.1.20/24 dev s1")
    os.system("sudo ip addr del 192.168.2.20/24 dev s2")
    os.system("sudo ip addr del 192.168.3.20/24 dev s3")
    os.system("sudo ip addr del 192.168.4.20/24 dev s4")

    net.stop()

    os.system("sudo mn -c")


if __name__ == '__main__':
    setLogLevel('info')
    Main()
