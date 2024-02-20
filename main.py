import socket
import sys
import struct
import threading
from _socket import inet_ntoa


# receive a datagram
# receive a datagram
def receiveData(s):
    data = b''  # Initialize data as a bytes-like object
    try:
        data, _ = s.recvfrom(65565)  # Assign the first element of the tuple to data
    except socket.timeout:
        pass  # Handle the timeout exception
    except:
        print("An error happened: ")
        sys.exc_info()  # Exit the program
    return data

def getTypeofService(data):
        precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                      6: "Internetwork control", 7: "Network control"}
        delay = {0: "Normal delay", 1: "Low delay"}
        throughput = {0: "Normal throughput", 1: "High throughput"}
        reliability = {0: "Normal reliability", 1: "High reliability"}
        cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

        #   get the 3rd bit and shift right
        D = data & 0x10 #hexadecimal 10
        D >>= 4
        #   get the 4th bit and shift right
        T = data & 0x8
        T >>= 3
        #   get the 5th bit and shift right
        R = data & 0x4
        R >>= 2
        #   get the 6th bit and shift right
        M = data & 0x2
        M >>= 1
        #   the 7th bit is empty and shouldn't be analyzed

        tabs = '\n\t\t\t'
        TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
              reliability[R] + tabs + cost[M]
        return TOS

def icmp_packet(data):
    icmp_type,code,checksum= struct.unpack('!BBH',data[:4])
    return icmp_type,code,checksum, data[4:]

def tcp_segment(data):
    srcport,destport,sequence,ack,offset=struct.unpack('!HHLLH',data[:14])
    offset=(offset >> 12)*4
    flag_urg=offset & 32 >>5
    flag_ack = offset & 16 >> 4
    flag_psh = offset & 8 >> 3
    flag_rst=offset & 4 >>2
    flag_syn = offset & 2 >> 1
    flag_fin = offset & 1
    return srcport,destport,sequence,ack,offset,flag_ack,flag_syn,flag_fin,flag_rst,flag_urg,flag_psh,data[14:]

def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return src_port, dest_port, length, checksum,data[8:]
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
    #   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
    #   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags


def packetsniffer():
    # This line retrieves the IP address of the current machine's network interface.
    # socket.gethostname() gets the hostname of the machine,
    # and socket.gethostbyname() translates it to an IP address.
    HOST = socket.gethostbyname(socket.gethostname())

    # This line creates a raw socket. socket.AF_INET specifies the address family (AF_INET for IPv4),
    # socket.SOCK_RAW specifies the socket type (SOCK_RAW for raw sockets),
    # and socket.IPPROTO_IP specifies the protocol (IPPROTO_IP for IP packets).
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    #This line binds the raw socket to the specified IP address (HOST)
    #and port (0 in this case, which means any available port).
    s.bind((HOST, 0))

    # This line sets the socket options to include IP headers in the received packets.
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # This line enables promiscuous mode on the socket, allowing it to receive all
    # packets on the network interface, not just those intended for the machine.
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #  This line receives a packet (up to 65565 bytes) from the  network and prints it.
    #recvfrom() returns a tuple containing, the data received and the address from which it was received.
    flag=True
    while flag:
        data=receiveData(s)
        #print(data)
        #unpacks unpacks data from a given binary string according to a given format.
        #extracts the first 20 bytes of the data binary string,this is often the size of an IPv4 header.


        unpackedData= struct.unpack('!BBHHHBBH4s4s',data[:20])

        version_and_headerlength= unpackedData[0]
        version= version_and_headerlength >>4 #shift 4 time to right to get version only
        headerlength= version_and_headerlength& 0xF #mask to extract the length
        TOS = unpackedData[1]  # type of service
        totalLength = unpackedData[2]
        ID = unpackedData[3]  # identification
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1FFF
        TimeToLive = unpackedData[5]  # time to live
        protocolNr = unpackedData[6]
        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8]) #takes a packed ip v4 address and converts it to standard dotted notation
        destinationAddress = inet_ntoa(unpackedData[9])



        print ("An IP packet with the size %i was captured." % (unpackedData[2]))
        print ("Raw data: " , data)
        print ("\nParsed data")
        print ("Version:\t\t" + str(version))
        print ("Header Length:\t\t" + str(headerlength*4) + " bytes")
        print ("Type of Service:\t" + getTypeofService(TOS))
        print ("Length:\t\t\t" + str(totalLength))
        print ("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
        print ("Flags:\t\t\t" + getFlags(flags))
        print ("Fragment offset:\t" + str(fragmentOffset))
        print ("TTL:\t\t\t" + str(TimeToLive))
        print ("Protocol:\t\t" + str(protocolNr))
        print ("Checksum:\t\t" + str(checksum))
        print ("Source:\t\t\t" , sourceAddress)
        print ("Destination:\t\t" , destinationAddress)
        print("Payload:\n", data[20:])
        # Print payload data in hexadecimal format
        payload = data[20:]
        if protocolNr==1:
            icmp_type,code,checksum,data=icmp_packet(payload)
            print("Icmp_type:\t\t" + str(icmp_type))
            print("code:\t\t" + str(code))
            print("Checksum:\t\t" + str(checksum))
            print("Data:\t\t" + str(data))
        elif protocolNr==6:
            srcport,destport,sequence,ack,offset,flag_ack,flag_syn,flag_fin,flag_rst,flag_urg,flag_psh,data = tcp_segment(payload)
            print("srcport:\t\t" + str(srcport))
            print("Destination port:\t\t" + str(destport))
            print("Sequence:\t\t" + str(sequence))
            print("Acknowledgment:\t\t" + str(ack))
            print("Offset:\t\t" + str(offset))
            print("Data:\t\t" + str(data))
        elif protocolNr==17:
            src_port, dest_port, length, checksum,data = udp_segment(payload)
            print("Source Port:", src_port)
            print("Destination Port:", dest_port)
            print("Length:", length)
            print("Checksum:", checksum)
            print("Data:\t\t" + str(data))







        flag=False
        # disabled promiscuous mode, returning the socket to normal operation
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

sniffer_thread = threading.Thread(target=packetsniffer)
sniffer_thread.start()