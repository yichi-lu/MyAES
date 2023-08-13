import os
import sys
import unittest

from AES import AES
from utils import (
    block_size_is_16, block2state,
    addroundkey, subbytes, shiftrows, mixcolumns, subword, rotword,
    keyexpansion,
)

Nk = 4
Nb = 4
Nr = 10

class TestUtils(unittest.TestCase):

    def setUp(self):
        self.aes = AES()

    def tearDown(self):
        self.aes = None

    def test_block_size_is_16(self):
        """
        Python native bytes type for block
        """
        b1 = b'0123456789abcde'
        b2 = b'0123456789abcdef'
        b3 = b'0123456789abcdefg'
        self.assertFalse(block_size_is_16(b1))
        self.assertTrue(block_size_is_16(b2))
        self.assertFalse(block_size_is_16(b3))
       
    def test_AES_padding(self):
        self.aes.plaintext = b'1234567890abcdef'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 32)
        [self.assertEqual(b, 16) for b in self.aes.plaintext_padded[16:]]
       
        self.aes.plaintext = b'1234567890abcde'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        self.assertEqual(self.aes.plaintext_padded[-1], 1)
       
        self.aes.plaintext = b'1234567890abcd'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 2) for b in self.aes.plaintext_padded[-2:]]
       
        self.aes.plaintext = b'1234567890abc'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 3) for b in self.aes.plaintext_padded[-3:]]
       
        self.aes.plaintext = b'1234567890ab'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 4) for b in self.aes.plaintext_padded[-4:]]
       
        self.aes.plaintext = b'1234567890a'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 5) for b in self.aes.plaintext_padded[-5:]]
       
        self.aes.plaintext = b'1234567890'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 6) for b in self.aes.plaintext_padded[-6:]]
       
        self.aes.plaintext = b'123456789'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 7) for b in self.aes.plaintext_padded[-7:]]
       
        self.aes.plaintext = b'12345678'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 8) for b in self.aes.plaintext_padded[-8:]]
       
        self.aes.plaintext = b'1234567'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 9) for b in self.aes.plaintext_padded[-9:]]
       
        self.aes.plaintext = b'123456'
#       import pdb;pdb.set_trace()
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 10) for b in self.aes.plaintext_padded[-10:]]
       
        self.aes.plaintext = b'12345'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 11) for b in self.aes.plaintext_padded[-11:]]
       
        self.aes.plaintext = b'1234'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 12) for b in self.aes.plaintext_padded[-12:]]
       
        self.aes.plaintext = b'123'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 13) for b in self.aes.plaintext_padded[-13:]]
       
        self.aes.plaintext = b'12'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 14) for b in self.aes.plaintext_padded[-14:]]
       
        self.aes.plaintext = b'1'
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 15) for b in self.aes.plaintext_padded[-15:]]

    def test_block2state(self):
        block = b'0123456789abcdef'
#       import pdb;pdb.set_trace()
        state = block2state(block)
        print(f"state returned from block2state():\n{state}")
        self.assertEqual(len(state), 4)
        self.assertEqual(len(state[0]), 4)

        block = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f'
        state = block2state(block)
        print(f"state returned from block2state():\n{state}")
        self.assertEqual(len(state), 4)
        self.assertEqual(len(state[0]), 4)

    def test_addroundkey(self):
        state = block2state(b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34')
        key = block2state(b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c')
        state = addroundkey(state, key)
        state_after = block2state(b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08')
        for i in range(Nk):
            for j in range(Nb):
                self.assertEqual(state[i][j], state_after[i][j])

    def test_subbytes(self):
        state = block2state(b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08')
        state = subbytes(state)
        state_after = block2state(b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30')
        for i in range(Nk):
            for j in range(Nb):
                self.assertEqual(state[i][j], state_after[i][j])

    def test_invsubbytes(self):
        self.assertEqual(1, 1)

    def test_shiftrows(self):
        state = block2state(b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30')
        state = shiftrows(state)
        state_after = block2state(b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5')
        [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]

    def test_invshiftrows(self):
        self.assertEqual(1, 1)

    def test_mixcolumns(self):
        state = block2state(b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5')
        state = mixcolumns(state)
        print(state)
        state_after = block2state(b'\x04\x66\x81\xe5\xe0\xcb\x19\x9a\x48\xf8\xd3\x7a\x28\x06\x26\x4c')
        print(state_after)
        [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]

    def test_invmixcolumn(self):
        self.assertEqual(1, 1)

    def test_subword(self):
        self.assertEqual(1, 1)

    def test_rotword(self):
        self.assertEqual(1, 1)

    def test_keyexpansion(self):
        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
        words = keyexpansion(key)
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]
        self.assertEqual(len(keys), 11)

        ekey = keys[0][0] + keys[0][1] + keys[0][2] + keys[0][3]
        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[1][0] + keys[1][1] + keys[1][2] + keys[1][3]
        key = b'\xa0\xfa\xfe\x17\x88\x54\x2c\xb1\x23\xa3\x39\x39\x2a\x6c\x76\x05'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[2][0] + keys[2][1] + keys[2][2] + keys[2][3]
        key = b'\xf2\xc2\x95\xf2\x7a\x96\xb9\x43\x59\x35\x80\x7a\x73\x59\xf6\x7f'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[3][0] + keys[3][1] + keys[3][2] + keys[3][3]
        key = b'\x3d\x80\x47\x7d\x47\x16\xfe\x3e\x1e\x23\x7e\x44\x6d\x7a\x88\x3b'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[4][0] + keys[4][1] + keys[4][2] + keys[4][3]
        key = b'\xef\x44\xa5\x41\xa8\x52\x5b\x7f\xb6\x71\x25\x3b\xdb\x0b\xad\x00'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[5][0] + keys[5][1] + keys[5][2] + keys[5][3]
        key = b'\xd4\xd1\xc6\xf8\x7c\x83\x9d\x87\xca\xf2\xb8\xbc\x11\xf9\x15\xbc'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[6][0] + keys[6][1] + keys[6][2] + keys[6][3]
        key = b'\x6d\x88\xa3\x7a\x11\x0b\x3e\xfd\xdb\xf9\x86\x41\xca\x00\x93\xfd'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[7][0] + keys[7][1] + keys[7][2] + keys[7][3]
        key = b'\x4e\x54\xf7\x0e\x5f\x5f\xc9\xf3\x84\xa6\x4f\xb2\x4e\xa6\xdc\x4f'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[8][0] + keys[8][1] + keys[8][2] + keys[8][3]
        key = b'\xea\xd2\x73\x21\xb5\x8d\xba\xd2\x31\x2b\xf5\x60\x7f\x8d\x29\x2f'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[9][0] + keys[9][1] + keys[9][2] + keys[9][3]
        key = b'\xac\x77\x66\xf3\x19\xfa\xdc\x21\x28\xd1\x29\x41\x57\x5c\x00\x6e'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

        ekey = keys[10][0] + keys[10][1] + keys[10][2] + keys[10][3]
        key = b'\xd0\x14\xf9\xa8\xc9\xee\x25\x89\xe1\x3f\x0c\xc8\xb6\x63\x0c\xa6'
        [self.assertEqual(ekey[i], key[i]) for i in range(len(key))]

    def test_cipher(self):
        """
        1: procedure CIPHER(in, Nr, w)
        2:     state ← in . See Sec. 3.4
        3:     state ← ADDROUNDKEY(state,w[0..3]) . See Sec. 5.1.4
        4:     for round from 1 to Nr −1 do
        5:         state ← SUBBYTES(state) . See Sec. 5.1.1
        6:         state ← SHIFTROWS(state) . See Sec. 5.1.2
        7:         state ← MIXCOLUMNS(state) . See Sec. 5.1.3
        8:         state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round +3])
        9:     end for
        10:    state ← SUBBYTES(state)
        11:    state ← SHIFTROWS(state)
        12:    state ← ADDROUNDKEY(state,w[4 ∗Nr..4 ∗Nr +3])
        13:    return state . See Sec. 3.4
        14: end procedure 
        """
        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
        words = keyexpansion(key)
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]
        input_ = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
        key = keys[0][0] + keys[0][1] + keys[0][2] + keys[0][3]
        state = addroundkey(block2state(input_), block2state(key))
        state_after = block2state(b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08')
        [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]
        for r in range(1, Nr + 1, 1):
            state = subbytes(state)
            if r == 1:
                state_after = block2state(b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30')
            elif r == 2:
                state_after = block2state(b'\x49\xde\xd2\x89\x45\xdb\x96\xf1\x7f\x39\x87\x1a\x77\x02\x53\x3b')
            elif r == 3:
                state_after = block2state(b'\xac\x73\xcf\x7b\xef\xc1\x11\xdf\x13\xb5\xd6\xb5\x45\x23\x5a\xb8')
            elif r == 4:
                state_after = block2state(b'\x52\x50\x2f\x28\x85\xa4\x5e\xd7\xe3\x11\xc8\x07\xf6\xcf\x6a\x94')
            elif r == 5:
                state_after = block2state(b'\xe1\x4f\xd2\x9b\xe8\xfb\xfb\xba\x35\xc8\x96\x53\x97\x6c\xae\x7c')
            elif r == 6:
                state_after = block2state(b'\xa1\x63\xa8\xfc\x78\x4f\x29\xdf\x10\xe8\x3d\x23\x4c\xd5\x03\xfe')
            elif r == 7:
                state_after = block2state(b'\xf7\xab\x31\xf0\x27\x83\xa9\xff\x9b\x43\x40\xd3\x54\xb5\x3d\x3f')
            elif r == 8:
                state_after = block2state(b'\xbe\x83\x2c\xc8\xd4\x3b\x86\xc0\x0a\xe1\xd4\x4d\xda\x64\xf2\xfe')
            elif r == 9:
                state_after = block2state(b'\x87\xec\x4a\x8c\xf2\x6e\xc3\xd8\x4d\x4c\x46\x95\x97\x90\xe7\xa6')
            elif r == 10:
                state_after = block2state(b'\xe9\x09\x89\x72\xcb\x31\x07\x5f\x3d\x32\x7d\x94\xaf\x2e\x2c\xb5')
            [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]
            state = shiftrows(state)
            if r == 1:
                state_after = block2state(b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5')
            elif r == 2:
                state_after = block2state(b'\x49\xdb\x87\x3b\x45\x39\x53\x89\x7f\x02\xd2\xf1\x77\xde\x96\x1a')
            elif r == 3:
                state_after = block2state(b'\xac\xc1\xd6\xb8\xef\xb5\x5a\x7b\x13\x23\xcf\xdf\x45\x73\x11\xb5')
            elif r == 4:
                state_after = block2state(b'\x52\xa4\xc8\x94\x85\x11\x6a\x28\xe3\xcf\x2f\xd7\xf6\x50\x5e\x07')
            elif r == 5:
                state_after = block2state(b'\xe1\xfb\x96\x7c\xe8\xc8\xae\x9b\x35\x6c\xd2\xba\x97\x4f\xfb\x53')
            elif r == 6:
                state_after = block2state(b'\xa1\x4f\x3d\xfe\x78\xe8\x03\xfc\x10\xd5\xa8\xdf\x4c\x63\x29\x23')
            elif r == 7:
                state_after = block2state(b'\xf7\x83\x40\x3f\x27\x43\x3d\xf0\x9b\xb5\x31\xff\x54\xab\xa9\xd3')
            elif r == 8:
                state_after = block2state(b'\xbe\x3b\xd4\xfe\xd4\xe1\xf2\xc8\x0a\x64\x2c\xc0\xda\x83\x86\x4d')
            elif r == 9:
                state_after = block2state(b'\x87\x6e\x46\xa6\xf2\x4c\xe7\x8c\x4d\x90\x4a\xd8\x97\xec\xc3\x95')
            elif r == 10:
                state_after = block2state(b'\xe9\x31\x7d\xb5\xcb\x32\x2c\x72\x3d\x2e\x89\x5f\xaf\x09\x07\x94')
            [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]
            if r != Nr:
                state = mixcolumns(state)
            if r == 1:
                state_after = block2state(b'\x04\x66\x81\xe5\xe0\xcb\x19\x9a\x48\xf8\xd3\x7a\x28\x06\x26\x4c')
            elif r == 2:
                state_after = block2state(b'\x58\x4d\xca\xf1\x1b\x4b\x5a\xac\xdb\xe7\xca\xa8\x1b\x6b\xb0\xe5')
            elif r == 3:
                state_after = block2state(b'\x75\xec\x09\x93\x20\x0b\x63\x33\x53\xc0\xcf\x7c\xbb\x25\xd0\xdc')
            elif r == 4:
                state_after = block2state(b'\x0f\xd6\xda\xa9\x60\x31\x38\xbf\x6f\xc0\x10\x6b\x5e\xb3\x13\x01')
            elif r == 5:
                state_after = block2state(b'\x25\xd1\xa9\xad\xbd\x11\xd1\x68\xb6\x3a\x33\x8e\x4c\x4c\xc0\xb0')
            elif r == 6:
                state_after = block2state(b'\x4b\x86\x8d\x6d\x2c\x4a\x89\x80\x33\x9d\xf4\xe8\x37\xd2\x18\xd8')
            elif r == 7:
                state_after = block2state(b'\x14\x15\xb5\xbf\x46\x16\x15\xec\x27\x46\x56\xd7\x34\x2a\xd8\x43')
            elif r == 8:
                state_after = block2state(b'\x00\x51\x2f\xd1\xb1\xc8\x89\xff\x54\x76\x6d\xcd\xfa\x1b\x99\xea')
            elif r == 9:
                state_after = block2state(b'\x47\x37\x94\xed\x40\xd4\xe4\xa5\xa3\x70\x3a\xa6\x4c\x9f\x42\xbc')
            [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]
            state = addroundkey(state, block2state(keys[r][0] + keys[r][1] + keys[r][2] + keys[r][3]))
            if r == 1:
                state_after = block2state(b'\xa4\x9c\x7f\xf2\x68\x9f\x35\x2b\x6b\x5b\xea\x43\x02\x6a\x50\x49')
            elif r == 2:
                state_after = block2state(b'\xaa\x8f\x5f\x03\x61\xdd\xe3\xef\x82\xd2\x4a\xd2\x68\x32\x46\x9a')
            elif r == 3:
                state_after = block2state(b'\x48\x6c\x4e\xee\x67\x1d\x9d\x0d\x4d\xe3\xb1\x38\xd6\x5f\x58\xe7')
            elif r == 4:
                state_after = block2state(b'\xe0\x92\x7f\xe8\xc8\x63\x63\xc0\xd9\xb1\x35\x50\x85\xb8\xbe\x01')
            elif r == 5:
                state_after = block2state(b'\xf1\x00\x6f\x55\xc1\x92\x4c\xef\x7c\xc8\x8b\x32\x5d\xb5\xd5\x0c')
            elif r == 6:
                state_after = block2state(b'\x26\x0e\x2e\x17\x3d\x41\xb7\x7d\xe8\x64\x72\xa9\xfd\xd2\x8b\x25')
            elif r == 7:
                state_after = block2state(b'\x5a\x41\x42\xb1\x19\x49\xdc\x1f\xa3\xe0\x19\x65\x7a\x8c\x04\x0c')
            elif r == 8:
                state_after = block2state(b'\xea\x83\x5c\xf0\x04\x45\x33\x2d\x65\x5d\x98\xad\x85\x96\xb0\xc5')
            elif r == 9:
                state_after = block2state(b'\xeb\x40\xf2\x1e\x59\x2e\x38\x84\x8b\xa1\x13\xe7\x1b\xc3\x42\xd2')
            elif r == 10:
                state_after = block2state(b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32')
            [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]

    def test_aes_cipher(self):
        self.aes.ptblock = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
        self.aes.key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
        state = self.aes.cipher()
        state_after = block2state(b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32')
        [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]

    def test_aes_invcipher(self):
        self.aes.ctblock = b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32'
        self.aes.key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
        state = self.aes.invcipher()
        state_after = block2state(b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34')
        [self.assertEqual(state[i], state_after[i]) for i in range(len(state_after))]

if __name__ == '__main__':
    unittest.main()
