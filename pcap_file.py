import struct


class EthPCAPFile:
    def __init__(self, filename: str, mode: str):
        self.file = None
        # documentation: https://wiki.wireshark.org/Development/LibpcapFileFormat
        # ======== global header ========================
        """
        typedef struct pcap_hdr_s {
                guint32 magic_number;   /* magic number */
                guint16 version_major;  /* major version number */
                guint16 version_minor;  /* minor version number */
                gint32  thiszone;       /* GMT to local correction */
                guint32 sigfigs;        /* accuracy of timestamps */
                guint32 snaplen;        /* max length of captured packets, in octets */
                guint32 network;        /* data link type */
        } pcap_hdr_t;
        """
        # ======== global header ========================
        self.write_order = '>'                              # order bytes for writting, default is big-endian
        self.snaplen = 65549
        self.magic_num = 0xa1b2c3d4
        self.version_maj = 2
        self.version_min = 4
        self.network = 1
        fmt = self.write_order + 'I2Hi3I'
        self.pcap_hdr = struct.pack(fmt, self.magic_num,
                                    self.version_maj, self.version_min, 0, 0, self.snaplen, self.network)
        self.open(filename, mode)

    def open(self, filename: str, mode: str)-> None:
        self.close()
        assert mode in ('r', 'w', 'a'), 'Uncorrect file mode for pcap file.!!!'
        self.file = open(filename + '.pcap', mode + 'b')
        if self.file.mode == 'wb':
            self.file.write(self.pcap_hdr)
        elif self.file.mode == 'rb':
            self.read_order = '>'                                       # default order bytes for reading is big-endian
            fmt = f'{self.read_order}I'
            magic_num = struct.unpack(fmt, self.file.read(4))[0]
            if self.magic_num != magic_num:
                if magic_num != 0xd4c3b2a1:
                    self.close()
                    raise ValueError("Unknown format pcap file!!!")
                self.read_order = '<'                                   # set order bytes for reading is little-endian
            fmt = self.read_order + "2H"
            vmaj, vmin = struct.unpack(fmt, self.file.read(4))
            if vmaj != self.version_maj or vmin != self.version_min:
                self.close()
                raise ValueError("Unknown version pcap file!!!")
            fmt = self.read_order + "i3I"
            _1, _2, snaplen, network = struct.unpack(fmt, self.file.read(16))
            if self.network != network:
                self.close()
                raise ValueError("Unknown network pcap file!!!")

    def write(self, data: bytes, ts_sec: int, ts_usec = 0, orig_len = None)-> int:
        incl_len = len(data)
        assert incl_len <= self.snaplen, f'Data must be <= {self.snaplen} for writing in eth-pcap file!!! '
        fmt = f'{self.write_order}4I{incl_len}s'
        """
        typedef struct pcaprec_hdr_s {
            guint32 ts_sec; / * отметка времени секунд * /
            guint32 ts_usec; / * метка времени микросекунды * /
            guint32 incl_len; / * количество октетов пакета, сохраненного в файле * /
            guint32 orig_len; / * фактическая длина пакета * /
        } pcaprec_hdr_t;
        """
        if orig_len is None:
            orig_len = incl_len
        if orig_len < incl_len:
            orig_len = incl_len
        return self.file.write(struct.pack(fmt, ts_sec, ts_usec, incl_len, orig_len, data))

    def read(self)-> tuple:
        fmt = f'{self.read_order}4I'
        read_bytes = self.file.read(16)
        if len(read_bytes) < 16:
            return None
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, read_bytes)

        fmt = f'{self.read_order}{incl_len}s'
        read_bytes = self.file.read(incl_len)
        if len(read_bytes) == 0:
            return None
        if len(read_bytes) < incl_len:
            incl_len = len(read_bytes)
            fmt = f'{self.read_order}{incl_len}s'
        data = struct.unpack(fmt, read_bytes)[0]
        return ts_sec, ts_usec, orig_len, data

    def close(self):
        if self.file:
            self.file.close()
            del self.file
            self.file = None

    def __del__(self):
        self.close()


# if __name__ == "__main__":
#     import icmpheader
#     import ipv4header
#     from rfc1071_checksum import checksum
#     import datetime
#     import random
#     import time
#
#
#     file = EthPCAPFile('kek', 'w')
#
#     for i in range(1):
#         data = bytearray([random.randint(0, 255) for i in range(28)])
#         packet = bytearray(len(data) + icmpheader.ICMPHeader.Length + ipv4header.IPv4Header.MinLength + 14)
#
#         iph = ipv4header.IPv4Header(hversion=4, hlength=5, htotal_length=56, hid=1234, httl=127, hprotocol=1,
#                                     hsrc_addr='1.2.3.4', hdst_addr='4.3.2.1')
#         icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4EchoRequest, hcode=0)
#         icmpheader.icmpv4_set_id(icmph, 1234)
#         icmpheader.icmpv4_set_seq_num(icmph, 9876)
#
#         fmt = f'>{len(data)}s'
#         struct.pack_into(fmt, packet, 42, data)
#         icmph.write_bytes_into(packet, 34)
#         struct.pack_into('>H', packet, 36, checksum(packet[34:]))
#         iph.write_bytes_into(packet, 14)
#         struct.pack_into('>H', packet, 24, checksum(packet[14:]))
#         struct.pack_into('>6s6sH', packet, 0, b'\x01\x02\x03\x04\x05\x06', b'\x06\x05\x04\x03\x02\x01', 0x0800)
#
#         d = datetime.datetime.utcnow()
#         file.write(packet, d.second, d.microsecond)
#         if i % 10 == 0:
#             time.sleep(0.01)
#
#     file.close()
#
#     file = EthPCAPFile('kek', 'r')
#     for i in range(1):
#         data = file.read()
#         if data is not None:
#             print(f'{data[0]} sec {data[1]} msec')
#             packet = data[3]
#             print(packet[:14])
#             iph = ipv4header.IPv4Header(hbytes=packet[14:])
#             print(iph)
#             icmph = icmpheader.ICMPHeader(hbytes=packet[14 + iph.header_length * 4:])
#             print(icmph)
#             print(packet[14 + iph.header_length * 4 + icmph.Length:].hex())
#             print()
#         else:
#             break
#     file.close()