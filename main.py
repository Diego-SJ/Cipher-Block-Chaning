from io import open
import os
import re
from cmd import Cmd
import binaryEncryptionMethods as Bem
import manageFile as mf
os.system('clear')

class electronicCB(Cmd):
    def __init__(self):
        super().__init__()
        try:
            plainTextClean = mf.readFile('PlainText.txt','a')
        except LookupError:
            print('ERROR: File error.')
        else:
            self.plainText = plainTextClean

        # * Read configFile.txt
        try:
            iv = ''
            with open("configFile.txt","r") as configFile:
                for variables in configFile:
                    v2 = re.match(r".*#### accion: ([a-z]*)",variables)
                    if v2:
                        action = (v2.group(1))
                        if action == 'e' or action == 'd':
                            pass
                        else:
                            print(f'ERROR: acción de encriptado invalido.')
                            exit()
                    v3 = re.match(r".*#### metodo: ([1-3]*)",variables)
                    if v3:
                        method = (v3.group(1))
                        if method == '1' or method == '2' or method == '3':
                            pass
                        else:
                            print(f'ERROR: método invalido.')
                            exit()
                    v4 = re.match(r".*#### llave: ([-0-9]*)",variables)
                    if v4:
                        llaveg = (v4.group(1))

                    v5 = re.match(r".*#### IV: (\w*)",variables)
                    if v5:
                        iv = (v5.group(1))

            if len(iv) == 8:
                try:bytearray(int(iv, 2))
                except:
                    print(f'ERROR: la llave no es binaria.')
                    exit()
            else:
                print(f'ERROR: IV debe ser 8 bits.')
                exit()
            if method == '1':
                if len(llaveg) == 8:
                    try:bytearray(int(llaveg, 2))
                    except:
                        print(f'ERROR: la llave no es binaria.')
                        exit()
                else:
                    print(f'ERROR: la llave debe ser 8 bits.')
                    exit()
            if method == '2':
                alphabet = "12345678"
                if len(llaveg) != len(alphabet):
                    print("ERROR: la llave debe tener una longitud de 8.")
                    exit()
                flag = 0
                for k in llaveg:
                    repeat = 0
                    for l in llaveg:
                        if l in alphabet:
                            if k == l:
                                repeat += 1
                        else:
                            flag += 1
                        if repeat > 1:
                            flag += 1
                if flag >= 1:
                    print("\nERROR! Un numero de la llave falta o esta repetido.")
                    exit()
            if method == '3':
                try:
                    alphaBin = '-01'
                    for i in llaveg:
                        if i not in alphaBin:
                            print(f'ERROR: la llave no es binaria.')
                            exit()
                except:
                    print(f'ERROR: la llave no es binaria.')
                    exit()
        except LookupError:
            print('ERROR: No se pudo leer el archivo.')
        else:
            self.METHOD = method
            self.KEY = llaveg
            self.IV = iv
            if action == 'e':
                self.encrypt()
            elif action == 'd':
                self.decrypt()
            else:
                exit()
        # * --------------------

    def encrypt(self):
        try:
            octetos = bytearray(self.plainText, 'utf8')
        except:
            print(f'ERROR: Check the path of the file.')
            exit()

        bytesArray = (' '.join(f'{x:b}'.rjust(8, '0') for x in octetos)).split()
        xor = Bem.XOR(bytesArray[0],self.IV)
        # * Choose a method
        if self.METHOD == '1': cN = Bem.CesarE(xor,self.KEY)
        if self.METHOD == '2': cN = Bem.MonoE(xor,self.KEY)
        if self.METHOD == '3': cN = Bem.DispE(xor,self.KEY)
        # * ---------------
        i = 1
        logProcess = '----- log -----\n\n'
        plainText = ''
        for P in bytesArray:
            logProcess += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            if i == 1:
                plainText += cN+' '
                logProcess += ("\nP{} -> {}"\
                "\n         xor -------> {}").format(i,P,xor)
                # * Choose a method
                if self.METHOD == '1': logProcess += "\nIV -> {}          ces -------> C{} -> {}".format(self.IV,i,cN)
                if self.METHOD == '2': logProcess += "\nIV -> {}          mon -------> C{} -> {}".format(self.IV,i,cN)
                if self.METHOD == '3': logProcess += "\nIV -> {}          dis -------> C{} -> {}".format(self.IV,i,cN)
                # * ---------------
                logProcess += "\n                  K-> {}\n".format(self.KEY)
            else:
                xor = Bem.XOR(P,cN)

                logProcess += ("\nP{} -> {}"\
                "\n         xor -------> {}").format(i,P,xor)
                # * Choose a method
                if self.METHOD == '1': logProcess += "\nC{} -> {}          ces -------> C{} -> {}".format((i-1),cN,i,Bem.CesarE(xor,self.KEY))
                if self.METHOD == '2': logProcess += "\nC{} -> {}          mon -------> C{} -> {}".format((i-1),cN,i,Bem.MonoE(xor,self.KEY))
                if self.METHOD == '3': logProcess += "\nC{} -> {}          dis -------> C{} -> {}".format((i-1),cN,i,Bem.DispE(xor,self.KEY))
                # * ---------------
                logProcess += "\n                  K-> {}\n".format(self.KEY)
                # * Choose a method
                if self.METHOD == '1': cN = Bem.CesarE(xor,self.KEY)
                if self.METHOD == '2': cN = Bem.MonoE(xor,self.KEY)
                if self.METHOD == '3': cN = Bem.DispE(xor,self.KEY)
                # * ---------------
                plainText += cN + ' '
            i += 1
        mf.createFile('log.txt',logProcess+'\n\nRESULT:\n'+plainText)
        mf.createFile('cipherText.txt',plainText)
        print('\nCOMPLETED PROCESS\n')
        exit()

    def decrypt(self):
        plainTextClean = mf.readFile('cipherText.txt','b')
        try:
            bytearray(int(x, 2) for x in plainTextClean.split())
        except:
            print(f'ERROR: File error.')
            exit()

        bytesArray = plainTextClean.split()

        # * Choose a method
        if self.METHOD == '1': dec = Bem.CesarD(bytesArray[0],self.KEY)
        if self.METHOD == '2': dec = Bem.MonoD(bytesArray[0],self.KEY)
        if self.METHOD == '3': dec = Bem.DispD(bytesArray[0],self.KEY)
        # * ---------------

        pN = Bem.XOR(dec,self.IV)
        i = 1
        logProcess = '----- log D -----\n\n'
        plainText = ''
        cN_aux = ''
        for cN in bytesArray:
            logProcess += ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            if i == 1:
                plainText += pN + ' '
                cN_aux = cN

                logProcess += ("\nC{} -> {}").format(i,cN)
                # * Choose a method
                if self.METHOD == '1': logProcess += "\n         ces -------> {}".format(dec)
                if self.METHOD == '2': logProcess += "\n         mon -------> {}".format(dec)
                if self.METHOD == '3': logProcess += "\n         dis -------> {}".format(dec)
                # * ---------------
                logProcess += ("\nK  -> {}          xor -------> P{} -> {} = {}").format(self.KEY,i,pN,chr(int(pN,2)))
                logProcess += "\n                IV -> {}\n".format(self.IV)
            else:
                # * Choose a method
                if self.METHOD == '1': dec = Bem.CesarD(cN,self.KEY)
                if self.METHOD == '2': dec = Bem.MonoD(cN,self.KEY)
                if self.METHOD == '3': dec = Bem.DispD(cN,self.KEY)
                # * ---------------
                pN = Bem.XOR(dec,cN_aux)
                plainText += pN + ' '

                logProcess += ("\nC{} -> {}").format(i,cN)
                # * Choose a method
                if self.METHOD == '1': logProcess += "\n         ces -------> {}".format(dec)
                if self.METHOD == '2': logProcess += "\n         mon -------> {}".format(dec)
                if self.METHOD == '3': logProcess += "\n         dis -------> {}".format(dec)
                # * ---------------
                logProcess += ("\nK  -> {}          xor -------> P{} -> {} = {}").format(self.KEY,i,pN,chr(int(pN,2)))
                logProcess += "\n                C{} -> {}\n".format((i-1),cN_aux)
                cN_aux = cN
            i += 1
        finalText = ''.join([chr(int(b, 2)) for b in plainText.split()])
        mf.createFile('decryptText.txt',finalText)
        mf.createFile('log.txt',logProcess+'\n\nRESULT:\n'+finalText)
        print('\nCOMPLETED PROCESS\n')
        exit()

app = electronicCB()
app.cmdloop()