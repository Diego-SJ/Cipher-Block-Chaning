"""
#module that encryp or decrypt a binary block
Created on Wed Apr 1 2020
@author: Diego Salas
"""

# Cesar Encription
def CesarE(inBlock,inKey):
    return '{0:b}'.format((int(inBlock,2) + int(inKey,2)) % 256).rjust(8, '0')

# Cesar Decrption
def CesarD(inBlock,inKey):
    return '{0:b}'.format((int(inBlock,2) - int(inKey,2)) % 256).rjust(8, '0')

# Monoalphabetical Encription
def MonoE(inBlock,inKey):
    output = ''
    for i in range(len(inBlock)):
        match = 0
        for j in inKey:
            if i == (int(j)-1):
                output += inBlock[match]
            match += 1
    return output

# Monoalphabetical Decrption
def MonoD(inBlock,inKey):
    output = ''
    for i in inKey:
        output += inBlock[int(i)-1]
    return output

# Dsiplacement Encription
def DispE(inBlock,inKey):
    output = ''
    if int(inKey,2) > 0:
        key = (int(inKey,2)) % 8
        for j in reversed(range(key)):
            output += inBlock[7-j]
        for i in range((len(inBlock))-key):
            output += inBlock[i]
    else:
        key = (int(inKey,2)) % -8
        for i in reversed(range((len(inBlock))-(key*-1))):
            output += inBlock[7-i]
        for j in range(key*-1):
            output += inBlock[j]
    return output

# Dsiplacement Decription
def DispD(inBlock,inKey):
    output = ''
    if int(inKey,2) > 0:
        key = (int(inKey,2) * -1) % -8
        for i in reversed(range((len(inBlock))-(key*-1))):
            output += inBlock[7-i]
        for j in range(key*-1):
            output += inBlock[j]
    else:
        key = (int(inKey,2) * -1) % -8
        for i in reversed(range((len(inBlock))-(key*-1))):
            output += inBlock[7-i]
        for j in range(key*-1):
            output += inBlock[j]
    return output

def XOR(b1,b2):
    return '{0:b}'.format(int(b1,2) ^ int(b2,2)).rjust(8, '0')
