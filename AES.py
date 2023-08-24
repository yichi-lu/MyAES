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
HALFBLOCKSIZE = 8
dt = np.dtype('B')                                          # unsigned byte

class AES():
    def __init__(self):
        self.key = None
        self.mode = None
        self.iv = None
        self.plaintext = None
        self.ptblock = np.ndarray((0,), dtype='B')
        self.plaintext_padded = np.ndarray((0,), dtype='B')
        self.ptblocks = None
        self.ctblocks = []
        self.ciphertext = None

    def IV(self):
        if not self.iv:
            self.iv = np.array([int(os.urandom(BLOCKSIZE).hex()[i:i + 2], 16) for i in range(0, 32, 2)])

    def padding(self):
        """
        pad plaintext according to PKCS#7
        """
        ptlen = len(self.plaintext)
        if ptlen > 0:
            if ptlen % BLOCKSIZE == 0:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(16, 16))
                self.plaintext_padded = np.concatenate((self.plaintext, np.repeat(16, 16)))
            elif ptlen % 16 == 1:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(15, 15))
            elif ptlen % 16 == 2:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(14, 14))
            elif ptlen % 16 == 3:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(13, 13))
            elif ptlen % 16 == 4:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(12, 12))
            elif ptlen % 16 == 5:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(11, 11))
            elif ptlen % 16 == 6:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(10, 10))
            elif ptlen % 16 == 7:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(9, 9))
            elif ptlen % 16 == 8:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(8, 8))
            elif ptlen % 16 == 9:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(7, 7))
            elif ptlen % 16 == 10:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(6, 6))
            elif ptlen % 16 == 11:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(5, 5))
            elif ptlen % 16 == 12:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(4, 4))
            elif ptlen % 16 == 13:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(3, 3))
            elif ptlen % 16 == 14:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(2, 2))
            elif ptlen % 16 == 15:
                self.plaintext_padded = np.append(self.plaintext, np.repeat(1, 1))
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
        key = np.asarray(keys[0]).T       # first expanded key
        state = addroundkey(block2state(self.ptblock), key)
        for r in range(Nr):
            state = subbytes(state)
            state = shiftrows(state)
            if r < (Nr - 1):
                state = mixcolumns(state)
            state = addroundkey(state, np.asarray(keys[r + 1]).T)

        return state

    def invcipher(self):
        words = keyexpansion(self.key)                                # the original key before key expansion
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]      # key expansion
        key = np.asarray(keys[Nr]).T       # first expanded key
        state = addroundkey(block2state(self.ctblock), key)
        for r in range(Nr, 0, -1):
            state = invshiftrows(state)
            state = invsubbytes(state)
            state = addroundkey(state, np.asarray(keys[r - 1]).T)
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
                    self.ptblock = np.array(np.bitwise_xor(byte16, self.iv))
                else:
                    self.ptblock = np.array(np.bitwise_xor(byte16, self.ctblocks[i - 1]))
                state = self.cipher()
                block = state2block(state)
                self.ctblocks.append(block)
            ctbs = np.concatenate([self.ctblocks[i] for i in range(len(self.ctblocks))])
            self.ciphertext = np.concatenate((self.iv, ctbs))

        elif mode == 'CTR':
            nonce = np.array([random.randbytes(HALFBLOCKSIZE)[j] for j in range(HALFBLOCKSIZE)])
            for i, byte16 in enumerate(self.ptblocks):
                self.ptblock = np.concatenate((nonce, np.array([int(f"{i:08}"[k]) for k in range(HALFBLOCKSIZE)])))
                block = state2block(self.cipher())
                block = np.array(np.bitwise_xor(block, byte16))
                self.ctblocks.append(block)

            ctbs = np.concatenate([self.ctblocks[i] for i in range(len(self.ctblocks))])
            self.ciphertext = np.concatenate((nonce, ctbs))

    def invcipher_mode(self, mode:str='CBC'):
        self.ptblocks = []
        if mode == 'CBC':
            self.iv = self.ciphertext[:BLOCKSIZE]

            for i, byte16 in enumerate(self.ctblocks):
                self.ctblock = byte16
                state = self.invcipher()
                block = state2block(state)
                if i == 0:
                    block = np.array(np.bitwise_xor(block, self.iv))
                else:
                    block = np.array(np.bitwise_xor(block, self.ctblocks[i - 1]))
                if i == len(self.ctblocks) - 1:
                    block = cleanup_last_block(block) 
                if block.all():
                    self.ptblocks.append(block)

        elif mode == 'CTR':
            nonce = np.array([self.ciphertext[:(HALFBLOCKSIZE)][j] for j in range(HALFBLOCKSIZE)])
            for i, byte16 in enumerate(self.ctblocks):
                self.ptblock = np.concatenate((nonce, np.array([int(f"{i:08}"[k]) for k in range(HALFBLOCKSIZE)])))
                block = state2block(self.cipher())
                block = np.array(np.bitwise_xor(block, byte16))
                if i == len(self.ctblocks) - 1:
                    block = cleanup_last_block(block) 
                if block is not None:
                    self.ptblocks.append(block)

        ptbs = np.concatenate([self.ptblocks[i] for i in range(len(self.ptblocks))])
        self.plaintext = b''.join(ptbs.view('|S1'))


if __name__ == '__main__':
    with open("buddha.txt", "rb") as fin:
        text = fin.read()
    print(f"plain text: {text.strip()}\n")

    aes = AES()
    aes.plaintext = np.ndarray((len(text.strip()),),
                         dtype='B',
                         buffer=text.strip(),
                         order='F'
                        )
    aes.key = np.ndarray((16,),
                         dtype='B',
                         buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                         order='F'
                        )
    aes.padding()
    aes.cipher_mode(mode='CBC')
    print(f"After cipher(CBC): {aes.ciphertext}\n")
    aes.invcipher_mode(mode='CBC')
    print(f"After invcipher(CBC): {aes.plaintext}\n")

    aes = AES()
    aes.plaintext = np.ndarray((len(text.strip()),),
                         dtype='B',
                         buffer=text.strip(),
                         order='F'
                        )
    aes.ptblock = np.ndarray((16,),
                             dtype='B',
                             buffer=b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
                            )
    aes.key = np.ndarray((16,),
                         dtype='B',
                         buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                         order='F'
                        )
    aes.padding()
    aes.cipher_mode(mode='CTR')
    print(f"After cipher(CTR): {aes.ciphertext}\n")
    aes.invcipher_mode(mode='CTR')
    print(f"After invcipher(CTR): {aes.plaintext}")

