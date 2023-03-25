import struct, socket
import utils
import Ipv4Packet

TCP_HEADER_FORMAT = "!HHLLBBHHH"
PSEUDO_HEADER_FORMAT = "!4s4sBBH"

class TcpPacket:
    """
    This class is meant to encapsulate a TCP header object.
    """

    def __init__(self, 
            src_ip: str, dest_ip: str, 
            src_port: int, dest_port: int, 
            seq_num: int, ack_num: int, 
            adv_win: int):
        """
        Purpose: Instantiates a TcpPacket object with an empty payload, a placeholder checksum value, and no flags.
                 The TcpPacket object is instantiated with the fields passed in.
        :param src_ip: str representing the IP address of the TcpPacket's source. 
        :param dest_ip: str representing the IP address of the TcpPacket's destination.
        :param src_port: int representing the port number of the TcpPacket's source.
        :param dest_port: int representing the port number of the TcpPacket's destination.
        :param seq_num: int representing the sequence number of the TcpPacket.
        :param ack_num: int representing the acknowledgement number of the TcpPacket.
        :param adv_win: int representing the advertised window of the TcpPacket.
        """
        self.source_ip = src_ip
        self.destination_ip = dest_ip
        self.source_port = src_port
        self.destination_port = dest_port
        self.sequence_number = seq_num
        self.acknowledgement_number = ack_num
        self.data_offset = 5 << 4 # 4 bits are reserved

        self.flags = 0  # real value is calculated later
        self.FIN, self.SYN, self.RST, self.PSH, self.ACK, self.URG = 0, 0, 0, 0, 0, 0

        self.advertised_window = adv_win
        self.checksum = 0  #real value is caluclated later
        self.urgent_pointer = 0
        self.data = None  # empty payload for now
    
    def __str__(self):
        """
        Purpose: Defines the string representation of a TcpPacket object.
        """
        tcp_str = f"({self.source_ip}:{self.source_port}) -> ({self.destination_ip}:{self.destination_port})\n"
        tcp_str += f"(SeqN / AckN) : ({self.sequence_number} / {self.acknowledgement_number})\n"
        tcp_str += f"TCP FLAGS: {self.FIN} {self.SYN} {self.RST} {self.PSH} {self.ACK} {self.URG}\n"
        return tcp_str

    def calculateFlags(self, tcp_flags: set) -> None:
        """
        Purpose: Takes in a set of TCP flags, sets the flags in that set to 1, and then calculates
                 the self.flags attribute of an outgoing TcpPacket object based on its flag attributes,
                 which may include: self.FIN, self.SYN, self.RST, self.PSH, self.ACK, self.URG.
                 Note that the casing of the items in tcp_flags does not matter.
        :param tcp_flags: set containing the TCP flags that should be set for this TcpPacket.
        :return: Void.
        """
        for flag in tcp_flags:
            if flag.upper() in ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]:
                setattr(self, flag.upper(), 1)
        if self.FIN == 1:
            self.flags |= self.FIN # << 0
        if self.SYN == 1:
            self.flags |= self.SYN << 1
        if self.RST == 1:
            self.flags |= self.RST << 2
        if self.PSH == 1:
            self.flags |= self.PSH << 3
        if self.ACK == 1:
            self.flags |= self.ACK << 4
        if self.URG == 1:
            self.flags |= self.URG << 5

    def pack(self, payload: str, tcp_flags=set()) -> bytes:
        """
        Purpose: Prepares the TcpPacket object to be sent out by packing it into a bytes object.
                 This involves encoding its payload, determining/calculating its flags attribute, 
                 and calculating its checksum. Note that calculating the checksum of the object
                 involves packing the TcpPacket with a dummy checksum of 0, calculating the real
                 checksum based on that and the packet pseud-header, and then splicing the real
                 checksum value into the packet. The final packet is then returned.
        :param payload: str representing the desired payload of the TCP packet object. 
        :param tcp_flags: set representing the TCP flags that should be set for this TcpPacket.
        :return: bytes representing the packed TcpPacket object ready to be sent.
        """
        self.data = payload.encode()  # encoding payload
        self.calculateFlags(tcp_flags)

        tcp_packet = struct.pack(
                TCP_HEADER_FORMAT,
                self.source_port,
                self.destination_port,
                self.sequence_number,
                self.acknowledgement_number,
                self.data_offset,
                self.flags,
                self.advertised_window,
                self.checksum,  # dummy value of 0
                self.urgent_pointer
        )
        pseudo_header = struct.pack(
                PSEUDO_HEADER_FORMAT,
                socket.inet_aton(self.source_ip),
                socket.inet_aton(self.destination_ip),
                0,
                socket.IPPROTO_TCP,
                len(tcp_packet) + len(self.data)
        )
        self.checksum = utils.getChecksum(pseudo_header + tcp_packet + self.data)
        # splicing in real checksum value:
        tcp_packet = (
                tcp_packet[ : 16]  # first 16 bytes (everything up to checksum)
                + struct.pack("!H", self.checksum)  # the new 16-bit checksum field
                + tcp_packet[18 : ]  # from the 18th byte (byte immediately after checksum)
                + self.data  # appending payload to end of modified packet
        )
        return tcp_packet
    
    @staticmethod
    def unpack(raw_packet: tuple) -> 'TcpPacket':
        """
        Purpose: A static method which takes in a raw packet sniffed from the network, 
                unpacks it, and parses it so that it can return a TcpPacket object 
                with the attributes of that received packet.
        :param raw_packet: tuple representing the raw packet returned from "socket.recvfrom()". 
        :return: The TcpPacket object representation of the raw_packet object passed in.
        """
        packet = raw_packet[0]

        iph = struct.unpack(Ipv4Packet.IPV4_HEADER_FORMAT, packet[0 : 20])
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        iph_length = (iph[0] & 0xF) * 4

        tcph = struct.unpack(
                TCP_HEADER_FORMAT, 
                packet[ iph_length : iph_length + 20]
        )
        src_port, dest_port = tcph[0], tcph[1]
        seq_num, ack_num = tcph[2], tcph[3]
        adv_win = tcph[6] 
        tcp_packet = TcpPacket(
                src_ip, dest_ip, 
                src_port, dest_port, 
                seq_num, ack_num, 
                adv_win
        )
        tcp_packet.data_offset = tcph[4] >> 4  # data_offset_reserved >> 4
        tcp_packet.checksum = tcph[7]
        tcp_packet.urgent_pointer = tcph[8]
        
        # Setting flags:
        tcp_packet.flags = tcph[5]
        tcp_packet.FIN = (tcph[5]) & 0b1
        tcp_packet.SYN = (tcph[5] >> 1) & 0b1
        tcp_packet.RST = (tcph[5] >> 2) & 0b1
        tcp_packet.PSH = (tcph[5] >> 3) & 0b1
        tcp_packet.ACK = (tcph[5] >> 4) & 0b1
        tcp_packet.URG = (tcph[5] >> 5) & 0b1

        h_size = iph_length + tcp_packet.data_offset * 4
        tcp_packet.data = packet[h_size : ]
        
        return tcp_packet

    @staticmethod
    def validateTcpChecksum(raw_packet: tuple) -> bool:
        """
        Purpose: A static method which takes in a raw packet sniffed from the network, excises 
                 that packet's TCP checksum value, and then re-computes that packet's TCP 
                 checksum value to see if the two checksum values match. This comparison is made 
                 to detect if the packet arrived corrupted. The bool returned represents whether
                 the two checksum values match
        :param raw_packet: tuple representing the raw packet returned from "socket.recvfrom()".
        :return: bool representing if the actual TCP checksum equals the calculated TCP checksum.
        """
        packet = raw_packet[0]

        # Getting select IP header info:
        iph = struct.unpack(Ipv4Packet.IPV4_HEADER_FORMAT, packet[0 : 20])
        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        # Working with TCP header:
        ip_data = packet[20 : ]  # splicing out IPv4 header
        tcph = struct.unpack(TCP_HEADER_FORMAT, ip_data[ : 20])
        tcp_checksum = tcph[7]
       
        pseudo_header = struct.pack(
            PSEUDO_HEADER_FORMAT,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
            0,
            socket.IPPROTO_TCP,
            len(ip_data),  # payload included
        )
        spliced_pkt = (
                ip_data[:16]
                + struct.pack("!H", 0)
                + ip_data[18:]
        )
        correct_tcp_checksum = utils.getChecksum(pseudo_header + spliced_pkt)
        return tcp_checksum == correct_tcp_checksum
