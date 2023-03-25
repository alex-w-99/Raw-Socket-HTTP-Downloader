import struct, socket, random
import utils
from TcpPacket import TcpPacket

IPV4_HEADER_SIZE = 20
IPV4_HEADER_FORMAT = "!BBHHHBBH4s4s"
DEFAULT_PROTOCOL = socket.IPPROTO_TCP

class Ipv4Packet:
    """
    This class is meant to encapsulate an IPv4 header object.
    """

    def __init__(self, source_ip: str, destination_ip: str):
        """
        Purpose: Instantiates an Ipv4Packet object with the fields passed in.
                 The Ipv4Packet object is also instantiated with a random IP ID, a version of
                 value 4, and an empty TCP packet (i.e., payload), among other attributes.
        :param source_ip: str representing the IP address of the Ipv4Packet's source.
        :param destination_ip: str representing the IP address of the Ipv4Packet's destination.
        """
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.total_length = IPV4_HEADER_SIZE  # default value for empty IPv4 packet
        self.id = random.randint(0, 50000)
        self.flags = 0
        self.ttl = 255
        self.protocol = DEFAULT_PROTOCOL
        self.checksum = 0  # real value is calculated later
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.tcp_packet = None  # empty payload for now

    def __str__(self):
        """
        Purpose: Defines the string representation of an Ipv4Packet object.
        """
        ip_str = f"IP_ID: {self.id}\n"
        if self.tcp_packet == None:
            ip_str += f"({self.source_ip}) -> ({self.destination_ip})\n"
        else:
            ip_str += self.tcp_packet.__str__()
        return ip_str

    def pack(self, tcp_packet: bytes) -> bytes:
        """
        Purpose: Prepares the Ipv4Packet object to be sent out by packing it into a bytes object.
                 This invovles first packing the Ipv4Packet object with a dummy checksum of 0,
                 calculating the real checksum based on that packet, and then splicing the real
                 checksum value into the packet. The final packet is then returned.
        :param tcp_packet: bytes representing the packed TcpPacket header object ready to be sent.
        :return: bytes representing the packet Ipv4Packet object ready to be sent. 
        """
        self.total_length = len(tcp_packet) + IPV4_HEADER_SIZE
        self.tcp_packet = tcp_packet

        ipv4_packet = struct.pack(
                IPV4_HEADER_FORMAT,
                self.version << 4 | self.header_length,
                self.service_type,
                self.total_length,
                self.id,
                self.flags,
                self.ttl,
                self.protocol,
                self.checksum,  # dummy value of 0
                socket.inet_aton(self.source_ip),
                socket.inet_aton(self.destination_ip)
        )
        self.checksum = utils.getChecksum(ipv4_packet)
        # repacking the Ipv4Packet with the correct checksum:
        ipv4_packet = struct.pack(
                IPV4_HEADER_FORMAT,
                self.version << 4 | self.header_length,
                self.service_type,
                self.total_length,
                self.id,
                self.flags,
                self.ttl,
                self.protocol,
                self.checksum,
                socket.inet_aton(self.source_ip),
                socket.inet_aton(self.destination_ip)
        ) + self.tcp_packet
        return ipv4_packet
    
    @staticmethod
    def unpack(raw_packet: tuple) -> 'Ipv4Packet':
        """
        Purpose: A static method which takes in a raw packet sniffed from the network, 
                 unpacks it, and parses it so that it can return an Ipv4Packet object
                 with the attributes of that received packet. Note that this method
                 calls "TcpPacket.unpack(raw_packet)", so that the returned Ipv4Packet
                 object's tcp_packet attribute equals the TcpPacket object representation
                 of the raw_packet object passed in.
        :param raw_packet: tuple representing the raw packet returned from "socket.recvfrom()".
        :return: The Ipv4Packet object representation of the raw_packet object passed in.
        """
        packet = raw_packet[0]
        ip_header = packet[0 : 20]
        iph = struct.unpack(IPV4_HEADER_FORMAT, ip_header)
        
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        ipv4_packet = Ipv4Packet(src_ip, dest_ip)

        ipv4_packet.version = iph[0] >> 4
        #ipv4_packet.service_type = iph[9] & 0x0F
        
        flags_fragment = iph[4]
        ipv4_packet.flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF

        ipv4_packet.ttl = iph[5]
        ipv4_packet.protocol = iph[6]
        ipv4_packet.checksum = iph[7] 

        tcp_packet = TcpPacket.unpack(raw_packet)    
        ipv4_packet.tcp_packet = tcp_packet
       
        return ipv4_packet

    @staticmethod
    def validateIpv4Checksum(raw_packet) -> bool:
        """
        Purpose: A static method which takes in a raw packet sniffed from the network, excises
                 that packet's IPv4 checksum value, and then re-computes that packet's TCP
                 checksum value to see if the two checksum values match. This comparison is
                 made to detect if the packet arrived corrupted. The bool returned represents
                 whether the two checksum values match.
        :param raw_packet: tuple representing the raw packet returned from "socket.recvfrom()".
        :return: bool representing if the actual IPv4 checksum equals the calculated IPv4 checksum.
        """
        packet = raw_packet[0]

        ip_checksum = struct.unpack(IPV4_HEADER_FORMAT, packet[0 : 20])[7]    
        validating_ip_checksum = (
                packet[ : 10] 
                + struct.pack("!H", 0)
                + packet[12 : 20]
        )
        correct_ip_checksum = utils.getChecksum(validating_ip_checksum) 
        return correct_ip_checksum == ip_checksum
