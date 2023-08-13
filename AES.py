import os
import sys
import random

import numpy as np

from utils import *

Nk = 4                                                      # key length in words
                                                            # each word is 4-byte
Nb = 4                                                      # block size in words
Nr = 10                                                     # ROUNDS
BLOCKSIZE = 16                                              # bytes

class AES():
    def __init__(self):
        self.key = None
        self.mode = None
        self.iv = None
        self.plaintext = b''
        self.ptblock = b''
        self.plaintext_padded = b''
        self.ptblocks = None
        self.ctblocks = []
        self.ciphertext = ''

    def IV(self):
        if not self.iv:
            self.iv = os.urandom(BLOCKSIZE)

    def padding(self):
        """
        pad plaintext according to PKCS#7
        """
        ptlen = len(self.plaintext)
        if ptlen > 0:
            if ptlen % BLOCKSIZE == 0:
                self.plaintext_padded = self.plaintext + chr(int(b'10', 16)).encode('utf-8') * 16
            elif ptlen % 16 == 1:
                self.plaintext_padded = self.plaintext + chr(int(b'0F', 16)).encode('utf-8') * 15
            elif ptlen % 16 == 2:
                self.plaintext_padded = self.plaintext + chr(int(b'0E', 16)).encode('utf-8') * 14
            elif ptlen % 16 == 3:
                self.plaintext_padded = self.plaintext + chr(int(b'0D', 16)).encode('utf-8') * 13
            elif ptlen % 16 == 4:
                self.plaintext_padded = self.plaintext + chr(int(b'0C', 16)).encode('utf-8') * 12
            elif ptlen % 16 == 5:
                self.plaintext_padded = self.plaintext + chr(int(b'0B', 16)).encode('utf-8') * 11
            elif ptlen % 16 == 6:
                self.plaintext_padded = self.plaintext + chr(int(b'0A', 16)).encode('utf-8') * 10
            elif ptlen % 16 == 7:
                self.plaintext_padded = self.plaintext + chr(int(b'09', 16)).encode('utf-8') * 9
            elif ptlen % 16 == 8:
                self.plaintext_padded = self.plaintext + chr(int(b'08', 16)).encode('utf-8') * 8
            elif ptlen % 16 == 9:
                self.plaintext_padded = self.plaintext + chr(int(b'07', 16)).encode('utf-8') * 7
            elif ptlen % 16 == 10:
                self.plaintext_padded = self.plaintext + chr(int(b'06', 16)).encode('utf-8') * 6
            elif ptlen % 16 == 11:
                self.plaintext_padded = self.plaintext + chr(int(b'05', 16)).encode('utf-8') * 5
            elif ptlen % 16 == 12:
                self.plaintext_padded = self.plaintext + chr(int(b'04', 16)).encode('utf-8') * 4
            elif ptlen % 16 == 13:
                self.plaintext_padded = self.plaintext + chr(int(b'03', 16)).encode('utf-8') * 3
            elif ptlen % 16 == 14:
                self.plaintext_padded = self.plaintext + chr(int(b'02', 16)).encode('utf-8') * 2
            elif ptlen % 16 == 15:
                self.plaintext_padded = self.plaintext + chr(int(b'01', 16)).encode('utf-8') * 1
        self.ptblocks = [self.plaintext_padded[i:i + 16] for i in range(0, len(self.plaintext_padded), 16)]

    def cipher(self):
        """
        This method does not use mode
        self.plaintext: a block of plain text
        Nr: ROUNDS
        key: encrypt key
        """
        words = keyexpansion(self.key)                                # the original key before key expansion
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]      # key expansion
        key = keys[0][0] + keys[0][1] + keys[0][2] + keys[0][3]       # first expanded key
        state = addroundkey(block2state(self.ptblock), block2state(key))
        for r in range(Nr):
            state = subbytes(state)
            state = shiftrows(state)
            if r < (Nr - 1):
                state = mixcolumns(state)
            state = addroundkey(state, block2state(keys[r + 1][0] + keys[r + 1][1] + keys[r + 1][2] + keys[r + 1][3]))

        return state

    def invcipher(self):
        words = keyexpansion(self.key)                                # the original key before key expansion
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]      # key expansion
        key = keys[Nr][0] + keys[Nr][1] + keys[Nr][2] + keys[Nr][3]       # first expanded key
        state = addroundkey(block2state(self.ctblock), block2state(key))
        for r in range(Nr, 0, -1):
            state = invshiftrows(state)
            state = invsubbytes(state)
            state = addroundkey(state, block2state(keys[r - 1][0] + keys[r - 1][1] + keys[r - 1][2] + keys[r - 1][3]))
            if r > 1:
                state = invmixcolumns(state)
        return state

    def cipher_mode(self, mode:str='CBC'):
        """
        This method uses mode. CBC: Cipher Block Chaining; CTR: Counter
        in_: a block
        Nr: ROUNDS
        key: encrypt key
        """
        self.ctblocks = []
        if mode == 'CBC':
            if not self.iv:
                self.IV()

            for i, byte16 in enumerate(self.ptblocks):
                if i == 0:
                    self.ptblock = b''.join([(byte16[j] ^ self.iv[j]).to_bytes(1,'big') for j in range(len(self.iv))])
                else:
                    self.ptblock = b''.join([(byte16[j] ^ self.ctblocks[i - 1][j]).to_bytes(1,'big') for j in range(len(self.ctblocks[i - 1]))])
                state = self.cipher()
                block = state2block(state)
                self.ctblocks.append(block)
            self.ciphertext = self.iv + b''.join(self.ctblocks)

        elif mode == 'CTR':
            nonce = random.randbytes(8)
            for i, byte16 in enumerate(self.ptblocks):
                self.ptblock = nonce + i.to_bytes(8, 'big')
                block = state2block(self.cipher())
                block = b''.join([(block[j] ^ byte16[j]).to_bytes(1,'big') for j in range(len(byte16))])
                self.ctblocks.append(block)

            self.ciphertext = nonce + b''.join(self.ctblocks)

    def invcipher_mode(self, mode:str='CBC'):
        self.ptblocks = []
        if mode == 'CBC':
            self.iv = self.ciphertext[:BLOCKSIZE]

            for i, byte16 in enumerate(self.ctblocks):
                self.ctblock = byte16
                state = self.invcipher()
                block = state2block(state)
                if i == 0:
                    block = b''.join([(block[j] ^ self.iv[j]).to_bytes(1,'big') for j in range(len(block))])
                else:
                    block = b''.join([(block[j] ^ self.ctblocks[i - 1][j]).to_bytes(1,'big') for j in range(len(block))])
                if i == len(self.ctblocks) - 1:
                    block = cleanup_last_block(block) 
                if block:
                    self.ptblocks.append(block)

        elif mode == 'CTR':
            nonce = self.ciphertext[:(BLOCKSIZE // 2)]
            for i, byte16 in enumerate(self.ctblocks):
                self.ptblock = nonce + i.to_bytes((BLOCKSIZE // 2), 'big')
                block = state2block(self.cipher())
                block = b''.join([(block[j] ^ byte16[j]).to_bytes(1,'big') for j in range(len(byte16))])
                if i == len(self.ctblocks) - 1:
                    block = cleanup_last_block(block) 
                if block:
                    self.ptblocks.append(block)

        self.plaintext = b''.join(self.ptblocks)



if __name__ == '__main__':
    with open("buddha.txt", "rb") as fin:
        text = fin.read()
    aes = AES()
    aes.plaintext = text.strip()
    aes.key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    aes.padding()
    aes.cipher_mode(mode='CBC')
    print(f"After cipher(CBC): {aes.ciphertext}\n")
    aes.invcipher_mode(mode='CBC')
    print(f"After invcipher(CBC): {aes.plaintext}\n")

    aes = AES()
    aes.plaintext = text.strip()
    aes.key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    aes.padding()
    aes.cipher_mode(mode='CTR')
    print(f"After cipher(CTR): {aes.ciphertext}\n")
    aes.invcipher_mode(mode='CTR')
    print(f"After invcipher(CTR): {aes.plaintext}")

