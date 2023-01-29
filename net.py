from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController
import os

class TwoSwitchTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1', mac="00:00:00:00:11:11", ip="192.168.5.1/24")
        h2 = self.addHost('h2', mac="00:00:00:00:11:12", ip="192.168.5.2/24")

        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(s1, s2)

def configure_resolv_conf_to_mininet_copology():
    os.system("echo 'nameserver 192.168.5.1'|tee -a /etc/resolv.conf")
    os.system("echo 'nameserver 192.168.5.2'|tee -a /etc/resolv.conf")
    os.system("sed -i 's/nameserver 127.0.0.53/#nameserver 127.0.0.53/' /etc/resolv.conf")
    os.system("sed -i 's/options edns0 trust-ad/#options edns0 trust-ad/' /etc/resolv.conf")

def restore_resolv_conf():
    os.system("sed -i 's/nameserver 192.168.5.1//' /etc/resolv.conf")
    os.system("sed -i 's/nameserver 192.168.5.2//' /etc/resolv.conf")
    os.system("sed -i 's/#nameserver 127.0.0.53/nameserver 127.0.0.53/' /etc/resolv.conf")
    os.system("sed -i 's/#options edns0 trust-ad/options edns0 trust-ad/' /etc/resolv.conf")

if __name__ == '__main__':
    print("Load dns nameserver")
    configure_resolv_conf_to_mininet_copology()
    print("DNS server was loaded")
    setLogLevel('info')
    topo = TwoSwitchTopo()
    c1 = RemoteController('c1')
    net = Mininet(topo=topo, controller=c1)
    net.start()

    print("Topology is up, adding new switch and link")

    CLI(net)
    net.stop()
    print("Restore previous DNS server")
    restore_resolv_conf()
    print("DNS was restored")