import threading, random
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP

PRIVATE_IFACE = "eth0"
PRIVATE_IP = "10.0.0.2"

PUBLIC_IFACE = "eth1"
PUBLIC_IP = "172.16.20.2"

SERVER_IP = "172.16.20.100"
PUBLIC_PORT = random.randint(1024, 65535) #generates a random port number for the public side 
dict = {}

def process_pkt_private(pkt: Packet):   
    if pkt.sniffed_on == PRIVATE_IFACE:
        print("received pkt from private interface", pkt.sniffed_on, pkt.summary())
        #pkt.show()
        if ICMP in pkt:
            if pkt[IP].dst == SERVER_IP:
                print('\tICMP Packet captured on private interface ', pkt[ICMP].id)
                
                #store client IP in dict using ICMP ID
                dict[pkt[ICMP].id]=pkt[IP].src

                # Create a new IP packet with specified src and dst                
                pkt = IP(src=PUBLIC_IP, dst=SERVER_IP) / pkt[ICMP]
                print('\t Created new packet 1')

                # Send the new packet over the public interface
                send(pkt, iface=PUBLIC_IFACE, verbose=False)
                print('\tSent new packet 1', pkt.sniffed_on, pkt.summary())


        elif TCP in pkt:
            if pkt[IP].dst != SERVER_IP: #used to filter random IPs
                pass
            else:
                print('\tTCP Packet captured on private interface')
                #creates a key with a list of 2 values, the original src IP and sport
                dict[PUBLIC_PORT] = [pkt[IP].src, pkt[TCP].sport] 

                # Modify IP packet with specified src and dst
                #assigns the router's public side IP as the src IP and TCP fields to the new_pkt
                new_pkt = IP(src=PUBLIC_IP, dst=SERVER_IP) / pkt[TCP] 
                
                #reset chksum in TCP field to be recalculated
                new_pkt[TCP].chksum = None 
                
                #assigns the rng port as the src port
                new_pkt[TCP].sport = PUBLIC_PORT 
                
                #new_pkt.show()
                # Send the new packet over the public interface
                send(new_pkt, iface=PUBLIC_IFACE, verbose=False)



def process_pkt_public(pkt: Packet):
    if pkt.sniffed_on == PUBLIC_IFACE:
        if pkt[IP].src == SERVER_IP: 
            print("received pkt from public interface", pkt.sniffed_on, pkt.summary())
            #pkt.show()
            if ICMP in pkt:     
                print('\tICMP Packet captured on public interface')
                
                # Modify IP packet with specified src and dst from from dict using ICMP ID
                pkt = IP(src=SERVER_IP, dst=dict[pkt[ICMP].id]) / pkt[ICMP]
                print('\t Created new packet 2')
            
                # Send the new packet over the private interface
                send(pkt, iface=PRIVATE_IFACE, verbose=False)
                print('\tSent new packet 2', pkt.sniffed_on, pkt.summary())
        

            elif TCP in pkt:
                if pkt[IP].src != SERVER_IP: #filters unwanted IPs
                    pass
                else:
                        #pkt.show()
                        print('\tTCP Packet captured on public interface')
                        # Create a new IP packet with specified src and dst
                        #creates a new_pkt with the server IP as the src iP and dst IP based on the public port
                        new_pkt = IP(src=SERVER_IP, dst=dict[PUBLIC_PORT][0]) / pkt[TCP] 

                        #chksum set to None to be recalculated 
                        new_pkt[TCP].chksum = None 
                        
                        #assigns corresponging dport based on public port num
                        new_pkt[TCP].dport = dict[PUBLIC_PORT][1] 
                        
                        #new_pkt.show()
                        # Send the new packet over the public interface
                        send(new_pkt, iface=PRIVATE_IFACE, verbose=False)

def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter="tcp")

def public_listener():
    print("sniffing packets on the public interface")
    sniff(prn=process_pkt_public, iface=PUBLIC_IFACE, filter="tcp")

def main():

    thread1 = threading.Thread(target=private_listener)
    thread2 = threading.Thread(target=public_listener)

    print("starting multiple sniffing threads...")
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

main()
