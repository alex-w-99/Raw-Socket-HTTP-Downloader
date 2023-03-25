import sys, socket, struct, urllib.parse

def getCommandLineArguments() -> str:
    """
    Purpose: Gets user's comman line arguments, parses them, and ensures their validity.
    :return: str representing the second command line argument.
    """
    argv = sys.argv
    if len(argv) == 2:  # 2 args -> "./rawhttpget [url]"
        URL = argv[1]
        return URL
    else:
        print("Bad command line arguments. Please try again.", file=sys.stderr)
        print("Arguments should be of the form: \"sudo ./rawhttpget [url]\"\n", file=sys.stderr)
        sys.exit(1)

def getLocalIpAddress() -> str:
    """
    Purpose: Gets the IP adadress of the local machine and returns it.
    :return: str representing the local IP address.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect( ("8.8.8.8", 80) )
    local_ip_address = s.getsockname()[0]
    s.close()
    return local_ip_address

def getAvailablePortNumber() -> int:
    """
    Purpose: Finds a valid local port that is not busy to send traffic on.
    :return: int representing the number of a valid, not busy local port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind( ("", 0) )
        s.listen(1)
        available_port = s.getsockname()[1]
    return available_port
    
def buildHttpGetRequest(URL: str, host: str) -> str:
    """
    Purpose: Build an HTTP 1.1 GET request string, to be sent to the URL/host 
    :param URL: str representing the URL that the GET request will be sent to.
    :param host: str representing the network location part of the URL.
    :return: str representing the HTTP 1.1 GET request.
    """
    get_req = f"GET {URL} HTTP/1.1\r\n"
    get_req += f"Host: {host}\r\n"
    get_req += f"Connection: keep-alive\r\n\r\n"
    return get_req

def getChecksum(packet: bytes) -> int:
    """
    Purpose: Computes the correct checksum value of a packet.
    :param packet: bytes of the packet whose checksum should be computed.
    :return: int representing the correct checksum value of the packet.
    """
    if len(packet) % 2 != 0:
        packet += b'\x00'

    checksum = 0
    for i in range(0, len(packet), 2):
        checksum += (packet[i] << 8) + packet[i+1]
    
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    return ~checksum & 0xffff
    
def getFileName(URL: str) -> str:
    """
    Purpose: Determines the appropriate file name for the URL passed into it.
    :param URL: str representing the URL whose data will be downloaded into a file named 
                by this function.
    :return: str representing the appropriate file name.
    """
    if URL.endswith("/") or not urllib.parse.urlparse(URL).path:
        return "index.html"
    else:
        return URL.split("/")[-1]

def writePacketDataToFile(URL: str, fragmented_data_dict: dict) -> None:
    """
    Purpose: Sorts the packet payloads in ascending order of their sequence numbers, joins
             that data together, excises the HTTP header, determines the data format,
             and writes that data to a file (whose name is determined by the URL).
    :param URL: str representing the URL whose data has been downloaded and will be written;
                URL is fed into utils.getFileName() to determine appropriate file name.
    :param fragmented_data_dict: dict which contains received packet payloads to be saved;
                contains all received packet {sequence_number : data } pairs.
    :return: Void.
    """
    # Order the packet payloads (values) according to their sequence number (value) in asc, order:
    sorted_data_list = sorted(fragmented_data_dict.items())

    # Concatenate the binary data without any separator:
    data = b''.join([ t[1] for t in sorted_data_list ])

    # Separating the HTTP header and body:
    data_header, data_to_write = data.split(b'\r\n\r\n')[ : 2]  # first two

    # Remove all separators if transfer-encoding style is chunked:
    if b'Transfer-Encoding' in data_header:
        data_chunk_list = data_to_write.split(b'\r\n')
        data_to_write = b''.join([ data_chunk_list[i] for i in range(1, len(data_chunk_list), 2) ])

    # Writing data to local directory:
    with open(f"{getFileName(URL)}", "wb") as f:
        f.write(data_to_write)

    # Close file:
    f.close()
