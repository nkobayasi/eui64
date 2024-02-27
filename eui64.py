#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import datetime
import hashlib

def float2fixed(value, precision=32):
    n, value = divmod(value, 1)
    int_part = '{:x}'.format(int(n))
    float_part = ''
    while len(float_part) < precision//4:
        n, value = divmod(value * 16, 1)
        float_part += '{:x}'.format(int(n))
    return float_part

class MacAddress(object):
    def __init__(self, value):
        self.value = int(re.sub('[-:]', '', value), base=16)

    def octets(self, index):
        return self.value >> (40 - (index - 1) * 8) & 0xff

    @property
    def oui24(self):
        return self.value >> 24 & 0xffffff
    
    @property
    def eui64(self):
        return int('{:06x}fffe{:02x}{:02x}{:02x}'.format(self.oui24, self.octets(4), self.octets(5), self.octets(6)), base=16)

    @property
    def modified_eui64(self):
        return self.eui64 ^ 0x0200000000000000

# RFC4193

# 3.1.  Format
#
#    The Local IPv6 addresses are created using a pseudo-randomly
#    allocated global ID.  They have the following format:
#
#       | 7 bits |1|  40 bits   |  16 bits  |          64 bits           |
#       +--------+-+------------+-----------+----------------------------+
#       | Prefix |L| Global ID  | Subnet ID |        Interface ID        |
#       +--------+-+------------+-----------+----------------------------+
#
#       Prefix            FC00::/7 prefix to identify Local IPv6 unicast
#                         addresses.
#
#       L                 Set to 1 if the prefix is locally assigned.
#                         Set to 0 may be defined in the future.  See
#                         Section 3.2 for additional information.
#
#       Global ID         40-bit global identifier used to create a
#                         globally unique prefix.  See Section 3.2 for
#                         additional information.
#
#       Subnet ID         16-bit Subnet ID is an identifier of a subnet
#                         within the site.
#
#       Interface ID      64-bit Interface ID as defined in [ADDARCH].

# 3.2.2.  Sample Code for Pseudo-Random Global ID Algorithm
#
#    The algorithm described below is intended to be used for locally
#    assigned Global IDs.  In each case the resulting global ID will be
#    used in the appropriate prefix as defined in Section 3.2.
#
#      1) Obtain the current time of day in 64-bit NTP format [NTP].
#
#      2) Obtain an EUI-64 identifier from the system running this
#         algorithm.  If an EUI-64 does not exist, one can be created from
#         a 48-bit MAC address as specified in [ADDARCH].  If an EUI-64
#         cannot be obtained or created, a suitably unique identifier,
#         local to the node, should be used (e.g., system serial number).
#
#      3) Concatenate the time of day with the system-specific identifier
#         in order to create a key.
#
#      4) Compute an SHA-1 digest on the key as specified in [FIPS, SHA1];
#         the resulting value is 160 bits.
#
#      5) Use the least significant 40 bits as the Global ID.
#
#      6) Concatenate FC00::/7, the L bit set to 1, and the 40-bit Global
#         ID to create a Local IPv6 address prefix.
#
#    This algorithm will result in a Global ID that is reasonably unique
#    and can be used to create a locally assigned Local IPv6 address
#    prefix.

class UniqueLocalIPv6UnicastAddress(object):
    def _compress_hextets(self, hextets):
        best_doublecolon_start = -1
        best_doublecolon_len = 0
        doublecolon_start = -1
        doublecolon_len = 0
        for index in range(len(hextets)):
            if hextets[index] == '0':
                doublecolon_len += 1
                if doublecolon_start == -1:
                    # Start of a sequence of zeros.
                    doublecolon_start = index
                if doublecolon_len > best_doublecolon_len:
                    # This is the longest sequence of zeros so far.
                    best_doublecolon_len = doublecolon_len
                    best_doublecolon_start = doublecolon_start
            else:
                doublecolon_len = 0
                doublecolon_start = -1

        if best_doublecolon_len > 1:
            best_doublecolon_end = (best_doublecolon_start +
                                    best_doublecolon_len)
            # For zeros at the end of the address.
            if best_doublecolon_end == len(hextets):
                hextets += ['']
            hextets[best_doublecolon_start:best_doublecolon_end] = ['']
            # For zeros at the beginning of the address.
            if best_doublecolon_start == 0:
                hextets = [''] + hextets

        return hextets

    def _hextets(self, value):
        hextets = []
        for _ in range(128 - 16, 0, -16):
            hextets.append('%x' % (value >> _ & 0xffff))
        return hextets

    @property
    def hextets(self):
        #print(self._hextets(self.value))
        #return self._hextets(self.value)
        hex_str = '%032x' % self.value
        hextets = []
        for x in range(0, 32, 4):
            hextets.append('%x' % int(hex_str[x:x+4], 16))
        return hextets

    def _stringify(self):
        return ':'.join(self.hextets)

    def _compress(self):
        return ':'.join(self._compress_hextets(self.hextets))

    def __str__(self):
        return '%s/64' % self._compress()
    
    def __init__(self, macaddr):
        self.macaddr = macaddr

    @property
    def value(self):
        return (self.prefix | self.L) << 120 | self.globalId << 80 | self.subnetId << 64

    @property
    def prefix(self):
        return 0xfc
        
    @property
    def L(self):
        return 0x01

    @property
    def globalId(self):
        # 1. current time of day in 64-bit NTP
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        unix_epoch = int(now.timestamp())
        ntp64_timeofday = unix_epoch + int((datetime.date(1970, 1, 1) - datetime.date(1900, 1, 1)).total_seconds())
        ntp64_microsecond = now.microsecond
        # 2. EUI-64 identifier
        eui64 = self.macaddr.modified_eui64
        # 3. Concatenate the time of day with EUI-64 identifier in order
        # 4. SHA-1 digest 160 bits
        sha1 = hashlib.sha1()
        #sha1.update('{:08x}{}'.format(epoch, float2fixed(microsecond / 1000000.0)).decode('hex'))
        #sha1.update('{:08x}{:08x}'.format(epoch, microsecond).decode('hex'))
        #sha1.update('{:08x}{:08x}'.format(epoch, 0).decode('hex')) # treat microsecond to zero
        sha1.update(bytes.fromhex('{:08x}{}'.format(ntp64_timeofday, float2fixed(ntp64_microsecond / 1000000.0))))
        sha1.update(bytes.fromhex('{:016x}'.format(eui64)))
        digest = int(sha1.hexdigest(), base=16)
        # 5. least significant 40 bits
        #return eui64 & 0xffffffffff
        return digest & 0xffffffffff

    @property
    def subnetId(self):
        return 1

UniqueLocalAddress = UniqueLocalIPv6UnicastAddress
ULA = UniqueLocalIPv6UnicastAddress

def main():
    macaddr = MacAddress('9c:a3:ba:02:03:4d')
    print(macaddr.value)
    print(hex(macaddr.value))
    print(hex(macaddr.octets(1)))
    print(hex(macaddr.octets(2)))
    print(macaddr.modified_eui64)
    print(hex(macaddr.modified_eui64))
    print(hex(macaddr.eui64))
    ula = UniqueLocalIPv6UnicastAddress(macaddr=macaddr)
    print(ula._string())
    print(ula._compress())
    print(ula)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    epoch = int(now.timestamp())
    microsecond = int(now.microsecond)
    print('{}'.format(now.microsecond))
    print('{:08x}'.format(epoch))
    print('{:08x}'.format(microsecond))
    print(float(now.timestamp()).hex())
    print(float(microsecond/1000000.0).hex())
    print(float2fixed(microsecond/1000000.0))
    print(float2fixed(microsecond/1000000.0, 64))

if __name__ == '__main__':
    main()