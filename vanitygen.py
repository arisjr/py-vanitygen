#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#    coineva vanitygen.py
#    Copyright (C) 2016 February
#    1200 Web Development
#    http://1200wd.com/
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#
#    Script adjusted for a CTF purpouse.
#
#
#
import os
import sys
from bitcoinlib.keys import HDKey
import timeit
from time import sleep
import random
import multiprocessing

address = 'mscAn4dWmwJkuAR5gDmdXSYS3ampxHC4Ct'
witness_type = 'segwit'
processors = 8
parts = int((2**32)/processors)

def address_search(search_for=address, multiplier = 0):
    global witness_type
    global parts
    privkey = int(parts * multiplier)
    address = ''
    count = 0
    start = timeit.default_timer()

    #bech32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    #base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    #is_bech32 = True
    #is_base58 = True
    #for letter in search_for:
    #    if letter not in bech32:
    #        is_bech32 = False
    #    if letter not in base58:
    #        is_base58 = False
    #if not (is_bech32 or is_base58):
    #    raise ValueError(f"This is not a valid base58 or bech32 search string: {search_for}")
    #if is_base58 and not is_bech32:
    #    print ("witness type p2sh-segwit")
    #    witness_type = 'p2sh-segwit'


    #print(f"Searching for {search_for}, witness_type is {witness_type} (pid {os.getpid()})")
    print(f"Sstarting address search: process {multiplier} (pid {os.getpid()})")


    while not search_for in address:
        privkey += 1
        k = HDKey(witness_type='legacy', key = privkey, network='testnet', compressed=False) #forcing legacy for CTF
        address = k.address()
        count += 1
        if not count % 10000:
            print("(%d) Searched %d in %d seconds (pid %d) : %s - %d" % (multiplier, count, timeit.default_timer()-start, os.getpid(), address, privkey))
        if count == parts:
            print("Process (pid %d) did not find key in slice." % os.getpid())
            return

    print("Found address: %s" % address)
    print("Private key HEX: %s" % k.private_hex)
    print("Private key INT:  %d" % privkey)
    print("Time to execute: %d seconds" % (timeit.default_timer()-start))
    return((address, k.private_hex))

def check_finish(plist):
    for p in plist:
        if not p.is_alive():
            return True
    return False

def kill_em_all(plist):
    for p in plist:
        p.terminate()


def main():
    global address
    global processors
    # print(multiprocessing.cpu_count())
    print("Starting %d processes" % processors)
    ps = []
    for i in range(processors):
        print("Starting process %d" % i)
        p = multiprocessing.Process(target=address_search, kwargs={'search_for': address, 'multiplier': i})
        p.start()
        ps.append(p)

    while True:
        if check_finish(ps):
            kill_em_all(ps)
            sys.exit(0)
        sleep(.5)


    # print(ps)
    # print('Main process exiting')

if __name__ == '__main__':
    main()
