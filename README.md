# eui64

## Description
Modified EUI-64 as the least-significant 64 bits of a unicast network address or link-local address when stateless address autoconfiguration is used. IPv6 uses a modified EUI-64, treats MAC-48 as EUI-48 instead (as it is chosen from the same address pool) and inverts the local bit. This results in extending MAC addresses (such as IEEE 802 MAC address) to modified EUI-64 using only FF-FE (and never FF-FF) and with the local bit inverted.