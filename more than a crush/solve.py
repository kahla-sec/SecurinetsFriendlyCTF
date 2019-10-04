#!/usr/bin/env python
from scapy.all import *
#MORSE CHARS

mp = { 'A':'.-', 'B':'-...', 
                    'C':'-.-.', 'D':'-..', 'E':'.', 
                    'F':'..-.', 'G':'--.', 'H':'....', 
                    'I':'..', 'J':'.---', 'K':'-.-', 
                    'L':'.-..', 'M':'--', 'N':'-.', 
                    'O':'---', 'P':'.--.', 'Q':'--.-', 
                    'R':'.-.', 'S':'...', 'T':'-', 
                    'U':'..-', 'V':'...-', 'W':'.--', 
                    'X':'-..-', 'Y':'-.--', 'Z':'--..', 
                    '1':'.----', '2':'..---', '3':'...--', 
                    '4':'....-', '5':'.....', '6':'-....', 
                    '7':'--...', '8':'---..', '9':'----.', 
                    '0':'-----', ', ':'--..--', '.':'.-.-.-', 
                    '?':'..--..', '/':'-..-.', '-':'-....-', 
                    '(':'-.--.', ')':'-.--.-'} 
#EXTRACT RAW FLAG
def extract_flag():
    flag=""
    packets=rdpcap("hard.pcap")
    for pckt in packets :
        if pckt.haslayer(scapy.all.ICMP) :
            if pckt[scapy.all.ICMP].type==0:
                try:
                    flag+=chr(pckt[scapy.all.ICMP].id)
                except ValueError:
                    continue    
    return flag            

#MAIN

raw_flag=extract_flag()    
print("[+]Found Raw Flaaaaaaag : "+raw_flag)

#REPLACING DOT and DASH

flag=raw_flag.replace("DOT",".")
flag=flag.replace("DASH","-")
print("[+]Found PreeeFlaag "+flag)

#MORSE DECODING

flag = flag.split("{")[1].split("}")[0].split(" ")
result = ""
for i in flag:
    for key in mp:
        if mp[key] == i:
            result += key
print "flag: Securinets{" + result + "}"
