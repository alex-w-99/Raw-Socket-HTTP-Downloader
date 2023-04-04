# Raw Socket HTTP Downloader

This repository contains Python code for a program called `rawhttpget`, which downloads a file from a given HTTP URL using raw sockets. This project can be thought of as a type of `wget` that utilizes raw sockets and is restricted to HTTP communication. In particular, this program demonstrates a close understanding of the low-level operations of the Internet protocol stack by using `SOCK_RAW`/`IPPROTO_RAW` sockets to build/unpack the IPv4 and TCP headers for each outgoing/incoming packet. Please recall that a "raw socket" refers to a type of network socket that allows direct access to lower-level protocols in the network stack, allowing higher-level protocol abstractions (which are used by many applications) to be bypassed. Using raw sockets, `rawhttpget` can send and receive packets at the network layer, enabling the program to construct and send its own custom network packets (rather than relying on the OS to construct them). This program also features congestion and flow control, allowing it to pass stress tests that involve the downloading of relatively large files. 

This program is run using the command `sudo ./rawhttpget <URL>`, where `<URL>` is the HTTP URL of the file you wish to download. Note that this program requires root privileges on the OS (i.e., requires using `sudo`) due to the fact that it uses raw sockets. Please see a demo video of this program [linked here](https://youtu.be/xw9mefBVJo4).

Concepts covered in this project include (but are not limited to) network packet processing, low-level operations on the Internet protocol stack, IPv4/TCP protocol suite, sockets, congestion and flow control, kernel bypass techniques, performance tuning, high-performance network I/O, HTTP, iptables, etc.

Tested on Ubuntu 20.04.1. Please note that in order for this program to run correctly, the user must first use a special kernel bypassing technique (turning GRO off) and perform a minor configuration of the Linux kernel's built-in firewall (dropping outgoing TCP RST packets); both of these items are discussed in the "Getting Started" section below. 

## Getting Started

The following includes instructions for configuring your system to use this program:

- <ins>Turning GRO Off:</ins> In order for this program to work, the user needs to first use `ethtool` to turn off Generic Receive Offload (GRO) for the network interface card that is used for receiving packets. Turning GRO off is necessary to prevent the Linux kernel from automatically merging/coalescing packet data before these packets are delivered to the network stack (i.e., before they are delivered to `rawhttpget`); this could interfere with the ability of `rawhttpget` to parse incoming packets correctly. To turn GRO off, the user must first run the command `sudo ethtool -K <interface_name> gro off`, where `<interface_name>` is the name of the network machine that should turn GRO off. You can find the interface name with the command `ifconfig -a`. As you can see in my demo video, my network machine is `enp0s3`.
- <ins>Setting a Rule in Iptables:</ins> Although `rawhttpget` does this automatically, it is still worth discussing why this needs to be done. For context, iptables can be thought of as a firewall program for Linux. The command `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` sets a rule in `iptables` that drops outgoing TCP RST packets. More specifically, this rule prevents the kernel from sending RST packets in response to unexpected incoming packets; by default, when the kernel receives a packet it cannot handle, it will send an RST packet back to the sender as a part of the IP/TPC protocol, and is meant to inform the sender that the connection is not open, has been closed, etc. Setting this rule is necessary to avoid the problems this can cause when attempting to implement a custom IPv4/TCP stack using the raw sockets. 
- <ins>HTTP Only, etc.:</ins> This program was only built to support HTTP; things like HTTPS are *not* supported. Moreover, this program does not support redirects, nor does it handle HTTP status codes other than 200. 
- <ins>Execution Permission:</ins> This should go without saying, but `rawhttpget` needs execution permission. The command `chmod 755 rawhttpget` makes the program executable by the owner.
- <ins>Running the Program:</ins> After accounting for the items above, this program can be run using the command `sudo ./rawhttpget <URL>`, where `<URL>` is the HTTP URL of the file you wish to download.

## Implementation Details

- <ins>`rawhttpget`</ins>: The class containing `main`, the program entry point, and which executes the program. 
- <ins>`RawSockets.py`</ins>: A class that contains the send and receive raw sockets, as well as the methods needed to send and receive the right packets from these raw sockets. 
- <ins>`Ipv4Packet.py`</ins>: A class that encapsulated an IPv4 packet, containing the appropriate attributes and methods to pack itself, unpack a raw IPv4 packet into an IPv4Packet object, etc. 
- <ins>`TcpPacket.py`</ins>: A class that encapsulated a TCP packet, containing the appropriate attributes and methods to pack itself, unpack a raw TCP packet into a TcpPacket object, etc. 
- <ins>`utils.py`</ins>: A file containing various helper functions that are used in the other files, but which were general enough that they did not logically belong in those other files.
- <ins>`TimeoutException.py`</ins>: A very simple Python `Exception` class that is thrown when no packet destined for this program is received/sniffed within 60 seconds (see `RawSockets.py`).

## Areas for Future Improvement

- [ ] Implement support for HTTP status codes other than 200 and HTTP redirections.
- [ ] Implement support for downloading files over HTTPS.
- [ ] Create a download progress bar in `stdout`, similar to the one displayed when using `wget`. 

## Program Demo (Video)

- To see this program in action, please see a demo video of this program [linked here](https://youtu.be/xw9mefBVJo4).
  - Note that for each HTTP URL file downloaded using `rawhttpget`, the program `wget` is subsequently used on that same HTTP URL to download the same file. This is so the two output files can be compared using `diff`; `diff` prints any and all differences between two files, and prints nothing if the files are identical. The fact that `diff` does not print anything to `stdout` each time it is called shows that the files downloaded by `rawhttpget` and `wget` are identical.
  - Note the Wireshark window open on the righthand side of the demo video. Please recall that Wireshark is a network protocol analyzer tool used to capture and analyze network traffic (i.e., a packet sniffer). In the demo video, Wireshark filters for packets coming to and from the IP address associated with the file we are downloading from the given URL via `rawhttpget` (in this case, that happens to be 204.44.192.60). This allows us to see the program's successful connection setup (three-way handshake/SYN-ACK connection setup), the program's successful ACKing of all received packets (and re-requesting of dropped packets when needed), and the program's successful connection teardown (FIN-ACK connection teardown).

## Acknowledgements 

- Zhongwei Zhang, my partner for this project. 
- Professor Alden Jackson, my Computer Networking professor.

## Contact Information

- Alexander Wilcox
- Email: alexander.w.wilcox@gmail.com
