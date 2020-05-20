"""
#module that create or read a .txt file
Created on Wed Apr 1 2020
@author: Diego Salas
"""

# ! CREATE FILE
def createFile(name,content):
    outputFile = open(name,'w')
    outputFile.write(content)
    outputFile.close()

# ! READ FILE
def readFile(name,type):
    try:
        plainTextFile = open(name,'r', encoding='utf8')
        textFile = plainTextFile.readlines()
        plainTextFile.close()
    except:
        print('ERROR: File does not exist.')
        exit()
    if type == 'a':
        plainTextClean = ""
        for et in textFile:
            plainTextClean += et
    elif type == 'b':
        alphabet = '01 '
        plainText = ""
        plainTextClean = ""
        for tf in textFile:
            plainText += tf.replace("\n", " ").upper()
        for et in plainText:
            if et in alphabet:
                plainTextClean += et
            elif et == " ":
                plainTextClean += " "
            else:
                plainTextClean += ""

    return plainTextClean