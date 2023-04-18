import socket
import threading
import bitarray
import argparse
import queue
from scapy.all import *
from scapy.layers.inet import *

SECOND_CLIENT_ADDRESS = ('127.0.0.1', 65012)
FIRST_CLIENT_ADDRESS = ('127.0.0.1', 65011)
PROXY_ADDRESS = ('127.0.0.1', 65010)
FIREWALL_ADDRESS = ('127.0.0.1', 65009)

class MyConcurrentCollection:
    def __init__(self):
        self.collection = queue.Queue()

    def append(self, x):
        self.collection.put(x)

    def pop(self):
        return self.collection.get()

    def __len__(self):
        return self.collection.qsize()

    def __str__(self):
        return f"{len(self)}"

    def print_collection(self):
        return self.collection.queue

    def empty(self):
        return self.collection.empty()

class Worker(threading.Thread):
    def __init__(self, input_collection: MyConcurrentCollection, callback=None):
        if not callback:
            raise NameError('callback not set')

        threading.Thread.__init__(self)
        self.daemon = True
        self.input_collection = input_collection
        self.callback = callback

    def run(self):
        while True:
            if not self.input_collection.empty():
                print("Run sniff")
                packet = self.input_collection.pop()
                self.callback(packet) 
            else:
                time.sleep(0.1)
                   

class Firewall:
    def __init__(self, callback=None, threads_count = 1):
        self.col = MyConcurrentCollection()
        self.consumers = [Worker(self.col, callback) for _ in range(threads_count)]


    def sniffer(self):
        print("run sniff")
        sniff(filter="src port 65011 and dst port 65009", prn=self.col.append, iface="lo")


    def run(self):
        for consumer in self.consumers:
            consumer.start()

        self.sniffer()

        for consumer in self.consumers:
            consumer.join()


def agent_normalize(pkt):
    ip_header = IP(src=pkt.getlayer(IP).src, dst=pkt.getlayer(IP).dst, ttl=64, tos=0x20)
    udp_header = UDP(sport=pkt['UDP'].sport, dport=SECOND_CLIENT_ADDRESS[1])
    packet_cov = ip_header / udp_header / pkt['UDP'].payload
    send(packet_cov, count=1)

def agent_fictitious_traffic(pkt):
    ip_header = IP(src=pkt.getlayer(IP).src, dst=pkt.getlayer(IP).dst)
    udp_header = UDP(sport=pkt['UDP'].sport, dport=SECOND_CLIENT_ADDRESS[1])
    packet_cov = ip_header / udp_header / pkt['UDP'].payload
    send(packet_cov, count=1)
    if random.randint(1, 101) <= 30:
        send(packet_cov, count=1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firewall defender emulation')
    parser.add_argument('defend_mode', default='normalize', const='normalize', nargs='?', choices=['normalize', 'fict'])
    args = parser.parse_args()
    match args.defend_mode:
        case "normalize":
            callback = agent_normalize
        case "fict":
            callback = agent_fictitious_traffic

    agent = Firewall(callback)
    agent.run()

