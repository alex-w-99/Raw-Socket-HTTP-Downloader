import socket, sys, time, random, urllib.parse
import utils
from TimeoutException import TimeoutException
from Ipv4Packet import Ipv4Packet
from TcpPacket import TcpPacket

DEFAULT_DESTINATION_PORT = 80
MSS = 1460  # max TCP payload size in bytes
MAX_WINDOW_SIZE = 65535
MAX_RETRANSMISSIONS = 3
MAX_RESETS = 3
TIMEOUT_SECONDS = 60

class RawSockets:
    """
    This class represents the object used to send/receive data. This includes both the
        raw send and receive sockets, as well as methods to communicate with the server.
    """

    def __init__(self, URL: str):
        """
        Purpose: Instantiates the RawSocket object with the URL passed in. Also instantiates
                 the RawSocket object with raw send and receive sockets, a random sequence
                 number, window information, etc.
        :param URL: str representing the server URL we wish to communicate with.
        """
        self.URL = URL
        parsed_url = urllib.parse.urlparse(URL)
        self.host, self.path = parsed_url.netloc, parsed_url.path

        self.send_socket, self.receive_socket = self.getSockets()

        self.source_ip = utils.getLocalIpAddress()
        self.source_port = utils.getAvailablePortNumber()
        self.destination_ip = socket.gethostbyname(self.host)
        self.destination_port = DEFAULT_DESTINATION_PORT

        self.sequence_number = random.randint(0, 2**32 - 1)  # seq# reps last byte ACKed by server
        self.acknowledgement_number = 0
        self.advertised_window = MAX_WINDOW_SIZE
    
        self.cwnd = 1  # 1 packet
        self.ssthresh = MAX_WINDOW_SIZE
        self.max_window = min(self.cwnd * MSS, MAX_WINDOW_SIZE)
        self.window_range = self.sequence_number + self.max_window
        
        self.seq_nums = set()  # used to detect duplicate packets
        self.sent_packet = (None, None, None)  # Ipv4Packet, TcpPacket, payload
        self.send_buffer = list()
        self.initiate_teardown = False  # indicates whether we have initiated teardown (sent FIN)
        self.total_resets = 0

    def createNewPacket(self, payload: str, tcp_flags: set) -> bytes:
        """
        Purpose: Takes in the desired payload and TCP flags, builds the corresponding
                 IPv4 and TCP packets, packs them into one packet, and returns it.
        :param payload: str representing the desired payload to be encoded and placed
                        into the TcpPacket as data.
        :param tcp_flags: set of strings representing the desired TcpPacket flags. 
        :return: bytes representing the packed up IPv4/TCP packet with the specified 
                 payload and TCP flags.
        """
        tcp_header = TcpPacket(
                self.source_ip, self.destination_ip,
                self.source_port, self.destination_port,
                self.sequence_number,
                self.acknowledgement_number,
                self.advertised_window
        )
        tcp_packet = tcp_header.pack(payload, tcp_flags) 

        ipv4_header = Ipv4Packet(self.source_ip, self.destination_ip)
        ipv4_packet = ipv4_header.pack(tcp_packet)

        self.sent_packet = ipv4_header, tcp_header, payload  # saving unpacked objects
        return ipv4_packet

    def sendPacket(self, pkt: bytes) -> None:
        """
        Purpose: Sends a packet to the server while pacing the rate at which it sends packets 
                 if need be. Note that for packets which should receive an ACK from the server, 
                 the sequence number is incremented by one; In the context of this project, 
                 our SYN, PSH/ACK (the HTTP GET request), and FIN packets should receive an ACK.
                 Also handles congestion control.
        :param pkt: bytes representing the packet we wish to send to the server.
        :return: Void.
        """
        if self.sequence_number <= self.window_range:
            self.send_socket.sendto(
                    pkt,
                    (self.destination_ip, self.destination_port)
            )
            tcp_packet = self.sent_packet[1]  # retrieving TcpPacket object of pkt
            if tcp_packet.SYN == 1 or tcp_packet.FIN == 1:
                self.sequence_number += 1
            elif len(tcp_packet.data) > 0:
                self.sequence_number = self.sequence_number + len(tcp_packet.data)
        else: 
            # If the sending data exceeds the window size, queue to a sender buffer;
            # Once another packet is received, window range could change s/t data can be sent again
            self.send_buffer.append(pkt)
            # Continuously loop until a packet is received:
            while len(self.send_buffer) > 0:
                receive_pkt = self.receivePacket()
                if receive_pkt:
                   j = 0 
                   while j < len(self.send_buffer):
                       if self.sequence_number <= self.window_range:
                           pkt_to_send = self.send_buffer.pop(0)
                           self.send_socket.sendto(
                                pkt_to_send,
                                (self.destination_ip, self.destination_port)
                           )   
                           j += 1
                       else:
                           # Add a snall delay before continuing to receive packets:
                           time.sleep(0.01)

    def receivePacket(self) -> Ipv4Packet:
        """
        Purpose: Listens to packets being sent to the network until it finds the packet that is
                 from the server and destined for this program. Requests re-transmission up to
                 3 times in case no packet intended for this program is received within 60
                 seconds or in case of bad checksum. Also performs congestion control.
        :return: Ipv4Packet representing the raw packet received from the server that was intended
                 for this program.
        """
        start_time = time.time()  # recording time of function call
        retransmissions = 0
        while True:
            try:
                if (time.time() - start_time) > TIMEOUT_SECONDS:  # check if re-transmission needed
                    raise TimeoutException()
                received_packet_raw = self.receive_socket.recvfrom(1000000)  # promiscuously sniff
            except (socket.timeout, TimeoutException):
                # Half the ssthresh and shrink cwnd to 1 if packet drop happens:
                self.ssthresh = self.cwnd * MSS / 2
                self.cwnd = 1 
                if retransmissions < MAX_RETRANSMISSIONS:  # check if we should re-send packet
                    retransmissions += 1

                    # Re-sending packet:
                    sent_ipv4_header, sent_tcp_header, sent_payload = self.sent_packet[0], self.sent_packet[1], self.sent_packet[2]
                    sent_ipv4_pkt = sent_ipv4_header.pack( sent_tcp_header.pack(sent_payload) )
                    self.sendPacket(sent_ipv4_pkt)
                    start_time = time.time()  # restarting the clock
                    continue
                else:
                    print("Packet could not be sent to server!", file=sys.stderr)
                    print("Exiting....", file=sys.stderr)
                    sys.exit(1)

            # Now that we have a packet, we can unpack it for inspection:
            received_packet = Ipv4Packet.unpack(received_packet_raw)

            # Check if packet is from the server, intended for this program, etc:
            if self.verifyPacketAddressing(received_packet) == False:
                continue

            # Check if duplicate packet (sequence numbers):
            if received_packet.tcp_packet.sequence_number in self.seq_nums:
                continue

            # Check if IPv4 and TCP checksum values are invalid:
            if (Ipv4Packet.validateIpv4Checksum(received_packet_raw) == False 
                    or TcpPacket.validateTcpChecksum(received_packet_raw) == False):
                # If either checksum is bad, then it may be corrupted; request re-transmission:
                retransmissions += 1
                sent_ipv4_header, sent_tcp_header, sent_payload = self.sent_packet[0], self.sent_packet[1], self.sent_packet[2]
                sent_ipv4_pkt = sent_ipv4_header.pack( sent_tcp_header.pack(sent_payload) )
                self.sendPacket(sent_ipv4_pkt)
                start_time = time.time()  # restarting the clock
                continue
            
            # Updating acknowledgement number attribute...
            data_length = len(received_packet.tcp_packet.data)
            # If received packet is a SYN:
            if self.sent_packet != (None, None, None) and self.sent_packet[1].SYN == 1:
                self.acknowledgement_number = received_packet.tcp_packet.sequence_number + 1
            # If received packet is FIN with no payload (server is initiating a connection teardown:
            elif received_packet.tcp_packet.FIN == 1 and data_length == 0:
                self.acknowledgement_number = received_packet.tcp_packet.sequence_number + 1
            # If received object is FIN with a payload: 
            elif received_packet.tcp_packet.FIN == 1 and data_length > 0:
                self.acknowledgement_number = received_packet.tcp_packet.sequence_number + data_length
            # Else general case:
            else:
                self.acknowledgement_number = (received_packet.tcp_packet.sequence_number \
                    + data_length) % 2**32

            # Congestion control implementation:
            dest_adv_window = received_packet.tcp_packet.advertised_window 
            self.ssthresh = dest_adv_window
            if self.cwnd >= 1000:
                self.cwnd = 1000 # cwnd maximum 1000
            elif self.cwnd * MSS < self.ssthresh:
                self.cwnd += 1   # slow start phase 
            else:
                self.cwnd += 1 / self.cwnd    # congestion avoidance phase 
            
            # Recalculating the window size: 
            self.max_window = min(self.cwnd * MSS, dest_adv_window)
            self.window_range = self.sequence_number + self.max_window 

            return received_packet
            
    def initThreeWayHandshake(self) -> None:
        """
        Purpose: Conducts a three-way handshake between this program and the server by
                 first sending a SYN packet to the server, then receiving the server's
                 SYN/ACK packet back, and finally sending the server an ACK packet.
                 If the server's SYN/ACK response has the wrong TCP flags, the program 
                 prints that the three-way handshake has failed and the program exits.
        :return: Void.
        """
        # 1. Send SYN:
        init_syn_pkt = self.createNewPacket("", {"SYN"})
        self.sendPacket(init_syn_pkt)
        # 2. Get SYN/ACK:
        init_synack_pkt = self.receivePacket()
        try:
            assert (
                    init_synack_pkt.tcp_packet.FIN == 0
                    and init_synack_pkt.tcp_packet.SYN == 1 
                    and init_synack_pkt.tcp_packet.RST == 0
                    and init_synack_pkt.tcp_packet.PSH == 0
                    and init_synack_pkt.tcp_packet.ACK == 1 
                    and init_synack_pkt.tcp_packet.URG == 0
            )
        except AssertionError as e:
            print("Three-way handshake could not be completed successfully!", file=sys.stderr)
            print("Exiting...", file=sys.stderr)
            sys.exit(1)
        # 3. Send ACK:
        init_ack_pkt = self.createNewPacket("", {"ACK"})
        self.sendPacket(init_ack_pkt)

    def tearDownConnection(self) -> None:
        """
        Purpose: Initiates the tearing down of the connection with the server by sending
                 the sever a FIN/ACK. This tells the server that our program is done sending
                 packets, and will only ACK back their packets from now (until they send us
                 a FIN packet).
        :return: Void.
        """
        fin_pkt = self.createNewPacket("", {"FIN", "ACK"})
        self.sendPacket(fin_pkt)
        self.initiate_teardown = True 

    def sendReceiveHttpGetRequest(self) -> dict:
        """
        Purpose: A highly specialized method meant to be run after self.initThreeWayHandshake(). 
                 Builds an HTTP 1.1 GET request, sends it to the server; initiates connection 
                 teardown; continuously receives packets from the server until it sends us FIN, 
                 and writes each packet from the server with a payload to a dictionary with 
                 key-value pairs of sequence number and payload. That dictionary is then returned.
                 This function also handles "RST" packets by resetting the connection up to 3 times.
        :return: dict containing key-value pairs of packet sequence numbers and packet data.
        """
        # Building and sending HTTP 1.1 GET request:
        get_req = utils.buildHttpGetRequest(self.URL, self.host)
        http_pkt = self.createNewPacket(get_req, {"PSH", "ACK"})
        self.sendPacket(http_pkt)

        # Initiating connection teardown:
        # If client wants to initiate teardown, uncomment line below:
        # self.tearDownConnection()

        # Continuously receive packets from server, writing to our dict, until it sends us FIN:
        fragmented_data_dict = dict()
        while True:
            incoming_packet = self.receivePacket()
            incoming_sequence_number = incoming_packet.tcp_packet.sequence_number

            # Checking TCP flags...
            # If server sends reset ("RST"):
            if incoming_packet.tcp_packet.RST == 1:
                if self.total_resets < MAX_RESETS:
                    self.total_resets += 1
                    self.resetAttributesAndConnection()
                    return self.sendReceiveHttpGetRequest()
                else:
                    print(f"Received TCP packet with\"RST\" flag from server more than {MAX_RESETS} times!", file=sys.stderr)
                    print("Exiting...", file=sys.stderr)
                    sys.exit(1)
            # If server initiates connection teardown by sending "FIN":
            elif incoming_packet.tcp_packet.FIN == 1 and self.initiate_teardown == False:
                print("Received TCP packet with \"FIN\" flag from server!")
                print("Closing connection...")
                self.sendPacket( self.createNewPacket("", {"FIN", "ACK"}) )
                break
            # If server sends "FIN" with empty payload:
            elif (incoming_packet.tcp_packet.FIN == 1
                    and self.initiate_teardown == True
                    and len(incoming_packet.tcp_packet.data) == 0):
                self.sendPacket( self.createNewPacket("", {"ACK"}) )
                break
            
            # Ignoring ACKs back from the server after sending the HTTP GET request:
            if len(incoming_packet.tcp_packet.data) == 0:
                continue

            # Writing received packet's sequence number and payload to dictionary:
            new_payload = incoming_packet.tcp_packet.data
            fragmented_data_dict[incoming_sequence_number] = new_payload

            # Acknowledging packet by sending back an "ACK":
            self.sendPacket( self.createNewPacket("", {"ACK"}) )
            
            # Adding the incoming packet's sequence number to the set attribute:
            self.seq_nums.add(incoming_sequence_number)

        return fragmented_data_dict    

    def verifyPacketAddressing(self, received_packet: Ipv4Packet) -> bool:
        """
        Purpose: Takes in the Ipv4Packet representation of a packet sniffed from the network
                 and determines if the packet is meant for this program; this determination is
                 made by evaluating the packet's IP protocol, the IP addresses of the packet's 
                 source and destination, and the port numbers of the packet's source and 
                 destination. A bool representing if all five fields match is returned.
        :param received_packet: Ipv4Packet representing the unpacked packet sniffed from 
                                the network.
        :return: bool representing if this received packet was indeed intended for this 
                 program.
        """
        return (
                received_packet.protocol == socket.IPPROTO_TCP
                and received_packet.source_ip == self.destination_ip 
                and received_packet.destination_ip == self.source_ip
                and received_packet.tcp_packet.source_port == self.destination_port
                and received_packet.tcp_packet.destination_port == self.source_port
        )

    def getSockets(self) -> tuple:
        """
        Purpose: Instantiates two SOCK_RAW/IPPROTO_RAW sockets, where the first socket
                 is used to send packets (protocol socket.IPPROTO_RAW) and the second
                 socket is used to receive packets (protocol socket.IPPROTO_TCP).
                 Upon success, the sockets are returned as a tuple; upon failure, an
                 error message is printed to stderr and the program exits.
        :return: tuple representing the send socket and receive socket, respectively. 
        """
        try:
            send_socket = socket.socket(
                    socket.AF_INET, 
                    socket.SOCK_RAW, 
                    socket.IPPROTO_RAW
            )
            receive_socket = socket.socket(
                    socket.AF_INET, 
                    socket.SOCK_RAW, 
                    socket.IPPROTO_TCP
            )
            receive_socket.settimeout(TIMEOUT_SECONDS)
        except socket.error as e:
            print(e, file=sys.stderr)
            print("Socket(s) could not be created!", file=sys.stderr)
            print("Exiting...", file=sys.stderr)
            sys.exit(1)
        return send_socket, receive_socket

    def closeSockets(self) -> None:
        """
        Purpose: Closes both raw socket attributes.
        :return: Void.
        """
        self.send_socket.close()
        self.receive_socket.close()

    def resetAttributesAndConnection(self) -> None:
        """
        Purpose: Called when the server sends a packet with the TCP flag "RST". Closes the currently
                 open raw sockets, resets select class attributes, and re-initializes the connection.
        :return: Void.
        """
        # Closing the raw sockets:
        self.closeSockets()

        # Resetting select attributes:
        self.send_socket, self.receive_socket = self.getSockets()
        self.source_port = utils.getAvailablePortNumber()

        self.sequence_number = random.randint(0, 2**32 - 1)
        self.acknowledgement_number = 0
        self.advertised_window = MAX_WINDOW_SIZE

        self.cwnd = 1
        self.ssthresh = MAX_WINDOW_SIZE
        self.max_window = min(self.cwnd * MSS, MAX_WINDOW_SIZE)
        self.window_range = self.sequence_number + self.max_window

        self.seq_nums = set()
        self.sent_packet = (None, None, None)
        self.send_buffer = list()
        self.initiate_teardown = False

        # Re-doing the 3-way handshake:
        self.initThreeWayHandshake()
