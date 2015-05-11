#!/usr/bin/python
import json
import hashlib
import sys
from itertools import permutations
from binascii import hexlify, unhexlify
from random import choice
from mnemonic import Mnemonic

def process(ctr, p_hex):
    print '(%i)' % ctr
    print 'input    : %s (%d bits)' % (p_hex, len(p_hex) * 4)
    
    p_mnemonic = mnemo.to_mnemonic(unhexlify(p_hex))
    print 'mnemonic : %s (%d words)' % (p_mnemonic, len(p_mnemonic.split(' ')))

    p_seed = hexlify(Mnemonic.to_seed(p_mnemonic, passphrase = ''))
    print 'seed     : %s (%d bits)' % (p_seed, len(p_seed) * 4)

wordlist = [w.strip() for w in open('BIP0039_wordlist.txt', 'r').readlines()]
def check(mnems):

    if len(mnems) % 3 > 0:
        return False
    try:
        idx = map(lambda x: bin(wordlist.index(x))[2:].zfill(11), mnems)
    except:
        return False
    b = ''.join(idx)
    l = len(b)
    d = b[:l / 33 * 32]
    h = b[-l / 33:]
    nd = unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l / 33 * 8))
    nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l / 33]

    return h == nh
    
if __name__ == '__main__':
    mnemo = Mnemonic('english')

    print sys.argv[1]
    my_mnemonic = sys.argv[1]

    mlist = my_mnemonic.split(' ')

    output = open("output.txt", "w")
    for mnems in permutations(mlist):
        if check(mnems):
	    print mnems
            output.write(' '.join(mnems)+"\n")
    output.close()   
