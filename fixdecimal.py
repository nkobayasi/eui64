#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import datetime

def fixedfloat(value, precision=32):
    n, value = divmod(value, 1)
    int_part = '{:x}'.format(int(n))
    float_part = ''
    while len(float_part) < precision//4:
        n, value = divmod(value * 16, 1)
        float_part += '{:x}'.format(int(n))
    return float_part

def float2hex(value, precision=32):
    m = re.search(r'(?P<sign>[-+])?0x(?P<integer>[0-9a-f]+)(\.(?P<fraction>[0-9a-f]+))?(p(?P<exponent>[-+0-9]+))?', float(value).hex(), re.IGNORECASE)
    if m is None:
        return value
    exponent = int(m.group('exponent'))
    if 0 <= exponent:
        return
    return '{:0{exponent}x}{}'.format(int(m.group('integer'), base=16), m.group('fraction'), exponent=-exponent)[0:precision//4]

def main():
    now = datetime.datetime.now()
    epoch = int(now.strftime('%s'))
    microsecond = now.microsecond / 1000000.0
    print(epoch)
    print('{:08x}'.format(epoch))
    print(microsecond)
    print(microsecond.hex())
    print(float2hex(microsecond))

if __name__ == '__main__':
    main()