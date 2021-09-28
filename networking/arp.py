import socket
import struct
from utilities import *
import binascii

class ARP:

    def __init__(self, raw_data):
        hardwareType, protocolType, hardwareSize, protoSize, opcode, sourceMAC, sourceIP, destMAC, destIP = struct.unpack('! 2s 2s 1s 1s 2s 6s 4s 6s 4s', raw_data[:28])
        self.hardwareType = binascii.hexlify(hardwareType)
        self.protocolType = binascii.hexlify(protocolType)
        self.hardwareSize = binascii.hexlify(hardwareSize)
        self.protoSize = binascii.hexlify(protoSize)
        self.opcode = binascii.hexlify(opcode)
        self.sourceMAC = get_mac_addr(sourceMAC)
        self.sourceIP = socket.inet_ntoa(sourceIP)
        self.destMAC = get_mac_addr(destMAC)
        self.destIP = socket.inet_ntoa(destIP)

