import os
import sys
import unittest

import numpy as np

from AES import AES
from utils import (
    block_size_is_16, block2state, state2block,
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
        Numpy dtype 'B' (or ubyte) for block
        """
        block = np.ndarray((15,), dtype='B', buffer=b'0123456789abcde')
        self.assertFalse(block_size_is_16(block))
        block = np.ndarray((16,), dtype='B', buffer=b'0123456789abcdef')
        self.assertTrue(block_size_is_16(block))
        block = np.ndarray((17,), dtype='B', buffer=b'0123456789abcdefg')
        self.assertFalse(block_size_is_16(block))

    def test_AES_padding(self):
        self.aes.plaintext = np.ndarray((16,),
                         dtype='B',
                         buffer=b'1234567890abcdef',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 32)
        [self.assertEqual(b, 16) for b in self.aes.plaintext_padded[16:]]

        self.aes.plaintext = np.ndarray((15,),
                         dtype='B',
                         buffer=b'1234567890abcde',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        self.assertEqual(self.aes.plaintext_padded[-1], 1)

        self.aes.plaintext = np.ndarray((14,),
                         dtype='B',
                         buffer=b'1234567890abcd',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 2) for b in self.aes.plaintext_padded[-2:]]

        self.aes.plaintext = np.ndarray((13,),
                         dtype='B',
                         buffer=b'1234567890abc',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 3) for b in self.aes.plaintext_padded[-3:]]

        self.aes.plaintext = np.ndarray((12,),
                         dtype='B',
                         buffer=b'1234567890ab',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 4) for b in self.aes.plaintext_padded[-4:]]

        self.aes.plaintext = np.ndarray((11,),
                         dtype='B',
                         buffer=b'1234567890a',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 5) for b in self.aes.plaintext_padded[-5:]]

        self.aes.plaintext = np.ndarray((10,),
                         dtype='B',
                         buffer=b'1234567890',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 6) for b in self.aes.plaintext_padded[-6:]]

        self.aes.plaintext = np.ndarray((9,),
                         dtype='B',
                         buffer=b'123456789',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 7) for b in self.aes.plaintext_padded[-7:]]

        self.aes.plaintext = np.ndarray((8,),
                         dtype='B',
                         buffer=b'12345678',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 8) for b in self.aes.plaintext_padded[-8:]]

        self.aes.plaintext = np.ndarray((7,),
                         dtype='B',
                         buffer=b'1234567',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 9) for b in self.aes.plaintext_padded[-9:]]

        self.aes.plaintext = np.ndarray((6,),
                         dtype='B',
                         buffer=b'123456',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 10) for b in self.aes.plaintext_padded[-10:]]

        self.aes.plaintext = np.ndarray((5,),
                         dtype='B',
                         buffer=b'12345',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 11) for b in self.aes.plaintext_padded[-11:]]

        self.aes.plaintext = np.ndarray((4,),
                         dtype='B',
                         buffer=b'1234',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 12) for b in self.aes.plaintext_padded[-12:]]

        self.aes.plaintext = np.ndarray((3,),
                         dtype='B',
                         buffer=b'123',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 13) for b in self.aes.plaintext_padded[-13:]]

        self.aes.plaintext = np.ndarray((2,),
                         dtype='B',
                         buffer=b'12',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 14) for b in self.aes.plaintext_padded[-14:]]

        self.aes.plaintext = np.ndarray((1,),
                         dtype='B',
                         buffer=b'1',
                         order='F'
                        )
        self.aes.padding()
        self.assertEqual(len(self.aes.plaintext_padded), 16)
        [self.assertEqual(b, 15) for b in self.aes.plaintext_padded[-15:]]

    def test_block2state(self):
        block = np.ndarray((16,), dtype='B', buffer=b'0123456789abcdef')
        state = block2state(block)
        print(f"state returned from block2state():\n{state}")
        self.assertEqual(state.shape, (4, 4))

        block = np.ndarray((16,), dtype='B', buffer=b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f')
        state = block2state(block)
        print(f"state returned from block2state():\n{state}")
        self.assertEqual(state.shape, (4, 4))

    def test_state2block(self):
        state = np.ndarray((4, 4), dtype='B', buffer=b'0123456789abcdef', order='F')
        print(f"state :\n{state}")
        block = state2block(state)
        print(f"block returned from state2block():\n{block}")
        self.assertEqual(block.shape, (16,))

    def test_addroundkey(self):
        state = np.ndarray((4, 4),
                             dtype='B',
                             buffer=b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34',
                             order='F'
                            )
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                           order='F'
                          )
        state = addroundkey(state, key)
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08',
                                 order='F'
                                )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    def test_subbytes(self):
        state = np.ndarray((4, 4),
                             dtype='B',
                             buffer=b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08',
                             order='F'
                            )
        state = subbytes(state)
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30',
                                 order='F'
                                )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    @unittest.skip("")
    def test_invsubbytes(self):
        pass

    def test_shiftrows(self):
        state = np.ndarray((4, 4),
                             dtype='B',
                             buffer=b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30',
                             order='F'
                            )
        state = shiftrows(state)
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5',
                                 order='F'
                                )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    @unittest.skip("")
    def test_invshiftrows(self):
        pass

    def test_mixcolumns(self):
        state = np.ndarray((4, 4),
                             dtype='B',
                             buffer=b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5',
                             order='F'
                            )
        state = mixcolumns(state)
        print(state)
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\x04\x66\x81\xe5\xe0\xcb\x19\x9a\x48\xf8\xd3\x7a\x28\x06\x26\x4c',
                                 order='F'
                                )
        print(state_after)
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    @unittest.skip("")
    def test_invmixcolumn(self):
        pass

    @unittest.skip("")
    def test_subword(self):
        pass

    @unittest.skip("")
    def test_rotword(self):
        pass

    def test_keyexpansion(self):
        key = np.ndarray((16,),
                           dtype='B',
                           buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                           order='F'
                          )
        words = keyexpansion(key)
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]
        self.assertEqual(len(keys), 11)

        ekey = np.concatenate((keys[0][0], keys[0][1], keys[0][2], keys[0][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[1][0], keys[1][1], keys[1][2], keys[1][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xa0\xfa\xfe\x17\x88\x54\x2c\xb1\x23\xa3\x39\x39\x2a\x6c\x76\x05',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[2][0], keys[2][1], keys[2][2], keys[2][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xf2\xc2\x95\xf2\x7a\x96\xb9\x43\x59\x35\x80\x7a\x73\x59\xf6\x7f',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[3][0], keys[3][1], keys[3][2], keys[3][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\x3d\x80\x47\x7d\x47\x16\xfe\x3e\x1e\x23\x7e\x44\x6d\x7a\x88\x3b',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[4][0], keys[4][1], keys[4][2], keys[4][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xef\x44\xa5\x41\xa8\x52\x5b\x7f\xb6\x71\x25\x3b\xdb\x0b\xad\x00',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[5][0], keys[5][1], keys[5][2], keys[5][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xd4\xd1\xc6\xf8\x7c\x83\x9d\x87\xca\xf2\xb8\xbc\x11\xf9\x15\xbc',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[6][0], keys[6][1], keys[6][2], keys[6][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\x6d\x88\xa3\x7a\x11\x0b\x3e\xfd\xdb\xf9\x86\x41\xca\x00\x93\xfd',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[7][0], keys[7][1], keys[7][2], keys[7][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\x4e\x54\xf7\x0e\x5f\x5f\xc9\xf3\x84\xa6\x4f\xb2\x4e\xa6\xdc\x4f',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[8][0], keys[8][1], keys[8][2], keys[8][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xea\xd2\x73\x21\xb5\x8d\xba\xd2\x31\x2b\xf5\x60\x7f\x8d\x29\x2f',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[9][0], keys[9][1], keys[9][2], keys[9][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xac\x77\x66\xf3\x19\xfa\xdc\x21\x28\xd1\x29\x41\x57\x5c\x00\x6e',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

        ekey = np.concatenate((keys[10][0], keys[10][1], keys[10][2], keys[10][3]))
        key = np.ndarray((4, 4),
                           dtype='B',
                           buffer=b'\xd0\x14\xf9\xa8\xc9\xee\x25\x89\xe1\x3f\x0c\xc8\xb6\x63\x0c\xa6',
                           order='F'
                          )
        self.assertEqual(ekey.tobytes('F'), key.tobytes('F'))

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
        key = np.ndarray((16,),
                           dtype='B',
                           buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                           order='F'
                          )
        words = keyexpansion(key)
        keys = [words[i:i + 4] for i in range(0, len(words), 4)]
        input_ = np.ndarray((4, 4),
                            dtype='B',
                            buffer=b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34',
                            order='F'
                           )
        key = np.asarray(keys[0]).T
        state = addroundkey(input_, key)
        state_after = np.ndarray((4, 4),
                            dtype='B',
                            buffer=b'\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08',
                            order='F'
                           )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))
        for r in range(1, Nr + 1, 1):
            state = subbytes(state)
            if r == 1:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30',
                                         order='F'
                                        )
            elif r == 2:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x49\xde\xd2\x89\x45\xdb\x96\xf1\x7f\x39\x87\x1a\x77\x02\x53\x3b',
                                         order='F'
                                        )
            elif r == 3:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xac\x73\xcf\x7b\xef\xc1\x11\xdf\x13\xb5\xd6\xb5\x45\x23\x5a\xb8',
                                         order='F'
                                        )
            elif r == 4:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x52\x50\x2f\x28\x85\xa4\x5e\xd7\xe3\x11\xc8\x07\xf6\xcf\x6a\x94',
                                         order='F'
                                        )
            elif r == 5:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xe1\x4f\xd2\x9b\xe8\xfb\xfb\xba\x35\xc8\x96\x53\x97\x6c\xae\x7c',
                                         order='F'
                                        )
            elif r == 6:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xa1\x63\xa8\xfc\x78\x4f\x29\xdf\x10\xe8\x3d\x23\x4c\xd5\x03\xfe',
                                         order='F'
                                        )
            elif r == 7:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xf7\xab\x31\xf0\x27\x83\xa9\xff\x9b\x43\x40\xd3\x54\xb5\x3d\x3f',
                                         order='F'
                                        )
            elif r == 8:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xbe\x83\x2c\xc8\xd4\x3b\x86\xc0\x0a\xe1\xd4\x4d\xda\x64\xf2\xfe',
                                         order='F'
                                        )
            elif r == 9:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x87\xec\x4a\x8c\xf2\x6e\xc3\xd8\x4d\x4c\x46\x95\x97\x90\xe7\xa6',
                                         order='F'
                                        )
            elif r == 10:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xe9\x09\x89\x72\xcb\x31\x07\x5f\x3d\x32\x7d\x94\xaf\x2e\x2c\xb5',
                                         order='F'
                                        )
            self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))
            state = shiftrows(state)
            if r == 1:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5',
                                         order='F'
                                        )
            elif r == 2:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x49\xdb\x87\x3b\x45\x39\x53\x89\x7f\x02\xd2\xf1\x77\xde\x96\x1a',
                                         order='F'
                                        )
            elif r == 3:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xac\xc1\xd6\xb8\xef\xb5\x5a\x7b\x13\x23\xcf\xdf\x45\x73\x11\xb5',
                                         order='F'
                                        )
            elif r == 4:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x52\xa4\xc8\x94\x85\x11\x6a\x28\xe3\xcf\x2f\xd7\xf6\x50\x5e\x07',
                                         order='F'
                                        )
            elif r == 5:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xe1\xfb\x96\x7c\xe8\xc8\xae\x9b\x35\x6c\xd2\xba\x97\x4f\xfb\x53',
                                         order='F'
                                        )
            elif r == 6:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xa1\x4f\x3d\xfe\x78\xe8\x03\xfc\x10\xd5\xa8\xdf\x4c\x63\x29\x23',
                                         order='F'
                                        )
            elif r == 7:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xf7\x83\x40\x3f\x27\x43\x3d\xf0\x9b\xb5\x31\xff\x54\xab\xa9\xd3',
                                         order='F'
                                        )
            elif r == 8:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xbe\x3b\xd4\xfe\xd4\xe1\xf2\xc8\x0a\x64\x2c\xc0\xda\x83\x86\x4d',
                                         order='F'
                                        )
            elif r == 9:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x87\x6e\x46\xa6\xf2\x4c\xe7\x8c\x4d\x90\x4a\xd8\x97\xec\xc3\x95',
                                         order='F'
                                        )
            elif r == 10:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xe9\x31\x7d\xb5\xcb\x32\x2c\x72\x3d\x2e\x89\x5f\xaf\x09\x07\x94',
                                         order='F'
                                        )
            self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))
            if r != Nr:
                state = mixcolumns(state)
            if r == 1:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x04\x66\x81\xe5\xe0\xcb\x19\x9a\x48\xf8\xd3\x7a\x28\x06\x26\x4c',
                                         order='F'
                                        )
            elif r == 2:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x58\x4d\xca\xf1\x1b\x4b\x5a\xac\xdb\xe7\xca\xa8\x1b\x6b\xb0\xe5',
                                         order='F'
                                        )
            elif r == 3:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x75\xec\x09\x93\x20\x0b\x63\x33\x53\xc0\xcf\x7c\xbb\x25\xd0\xdc',
                                         order='F'
                                        )
            elif r == 4:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x0f\xd6\xda\xa9\x60\x31\x38\xbf\x6f\xc0\x10\x6b\x5e\xb3\x13\x01',
                                         order='F'
                                        )
            elif r == 5:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x25\xd1\xa9\xad\xbd\x11\xd1\x68\xb6\x3a\x33\x8e\x4c\x4c\xc0\xb0',
                                         order='F'
                                        )
            elif r == 6:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x4b\x86\x8d\x6d\x2c\x4a\x89\x80\x33\x9d\xf4\xe8\x37\xd2\x18\xd8',
                                         order='F'
                                        )
            elif r == 7:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x14\x15\xb5\xbf\x46\x16\x15\xec\x27\x46\x56\xd7\x34\x2a\xd8\x43',
                                         order='F'
                                        )
            elif r == 8:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x00\x51\x2f\xd1\xb1\xc8\x89\xff\x54\x76\x6d\xcd\xfa\x1b\x99\xea',
                                         order='F'
                                        )
            elif r == 9:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x47\x37\x94\xed\x40\xd4\xe4\xa5\xa3\x70\x3a\xa6\x4c\x9f\x42\xbc',
                                         order='F'
                                        )
            self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))
            state = addroundkey(state, np.asarray(keys[r]).T)
            if r == 1:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xa4\x9c\x7f\xf2\x68\x9f\x35\x2b\x6b\x5b\xea\x43\x02\x6a\x50\x49',
                                         order='F'
                                        )
            elif r == 2:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xaa\x8f\x5f\x03\x61\xdd\xe3\xef\x82\xd2\x4a\xd2\x68\x32\x46\x9a',
                                         order='F'
                                        )
            elif r == 3:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x48\x6c\x4e\xee\x67\x1d\x9d\x0d\x4d\xe3\xb1\x38\xd6\x5f\x58\xe7',
                                         order='F'
                                        )
            elif r == 4:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xe0\x92\x7f\xe8\xc8\x63\x63\xc0\xd9\xb1\x35\x50\x85\xb8\xbe\x01',
                                         order='F'
                                        )
            elif r == 5:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xf1\x00\x6f\x55\xc1\x92\x4c\xef\x7c\xc8\x8b\x32\x5d\xb5\xd5\x0c',
                                         order='F'
                                        )
            elif r == 6:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x26\x0e\x2e\x17\x3d\x41\xb7\x7d\xe8\x64\x72\xa9\xfd\xd2\x8b\x25',
                                         order='F'
                                        )
            elif r == 7:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x5a\x41\x42\xb1\x19\x49\xdc\x1f\xa3\xe0\x19\x65\x7a\x8c\x04\x0c',
                                         order='F'
                                        )
            elif r == 8:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xea\x83\x5c\xf0\x04\x45\x33\x2d\x65\x5d\x98\xad\x85\x96\xb0\xc5',
                                         order='F'
                                        )
            elif r == 9:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\xeb\x40\xf2\x1e\x59\x2e\x38\x84\x8b\xa1\x13\xe7\x1b\xc3\x42\xd2',
                                         order='F'
                                        )
            elif r == 10:
                state_after = np.ndarray((4, 4),
                                         dtype='B',
                                         buffer=b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32',
                                         order='F'
                                        )
            self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    def test_aes_cipher(self):
        self.aes.ptblock = np.ndarray((16,),
                                      dtype='B',
                                      buffer=b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
                                     )
        self.aes.key = np.ndarray((16,),
                                  dtype='B',
                                  buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                                  order='F'
                                 )
        state = self.aes.cipher()
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32',
                                 order='F'
                                )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

    def test_aes_invcipher(self):
        self.aes.ctblock = np.ndarray((16,),
                                      dtype='B',
                                      buffer=b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32'
                                     )
        self.aes.key = np.ndarray((16,),
                                  dtype='B',
                                  buffer=b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c',
                                  order='F'
                                 )
        state = self.aes.invcipher()
        state_after = np.ndarray((4, 4),
                                 dtype='B',
                                 buffer=b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34',
                                 order='F'
                                )
        self.assertEqual(state.tobytes('F'), state_after.tobytes('F'))

if __name__ == '__main__':
    unittest.main()
