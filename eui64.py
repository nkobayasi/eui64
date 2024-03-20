#!/usr/bin/python
# -*- coding: utf-8 -*-

from functools import wraps
import re
import datetime
import hashlib
import ipaddress

def memoized(func):
    @wraps(func)
    def closure(*args, **kwargs):
        cls = args[0]
        attrname = '_memoized_{0}'.format(func.__name__)
        if not hasattr(cls, attrname):
            setattr(cls, attrname, func(*args, **kwargs))
        return getattr(cls, attrname)
    return closure

def fixedfloat(value, precision=32):
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
    def __init__(self, macaddr, subnet=1):
        if not isinstance(macaddr, MacAddress):
            macaddr = MacAddress(macaddr)
        self.macaddr = macaddr
        self._subnetId = subnet
    
    @property
    def address(self):
        return ipaddress.ip_address(self.value)

    @property
    def subnet(self):
        return ipaddress.ip_interface('%s/64' % self.address)

    def __str__(self):
        return str(self.subnet)
    
    def interface(self, interfaceId):
        return ipaddress.ip_interface('%s/128' % ipaddress.ip_address(self.value | (interfaceId & 0xffffffffffffffff)))

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
    @memoized
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
        #sha1.update('{:08x}{}'.format(epoch, fixedfloat(microsecond / 1000000.0)).decode('hex'))
        #sha1.update('{:08x}{:08x}'.format(epoch, microsecond).decode('hex'))
        #sha1.update('{:08x}{:08x}'.format(epoch, 0).decode('hex')) # treat microsecond to zero
        sha1.update(bytes.fromhex('{:08x}{}'.format(ntp64_timeofday, fixedfloat(ntp64_microsecond / 1000000.0))))
        sha1.update(bytes.fromhex('{:016x}'.format(eui64)))
        digest = int(sha1.hexdigest(), base=16)
        # 5. least significant 40 bits
        #return eui64 & 0xffffffffff
        return digest & 0xffffffffff

    @property
    def subnetId(self):
        return self._subnetId & 0xffff

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
    print(ula)
    print(ula.interface(1))
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    epoch = int(now.timestamp())
    microsecond = int(now.microsecond)
    print('{}'.format(now.microsecond))
    print('{:08x}'.format(epoch))
    print('{:08x}'.format(microsecond))
    print(float(now.timestamp()).hex())
    print(float(microsecond/1000000.0).hex())
    print(fixedfloat(microsecond/1000000.0))
    print(fixedfloat(microsecond/1000000.0, 64))

if __name__ == '__main__':
    main()