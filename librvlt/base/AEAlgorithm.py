#!/usr/bin/env python3
#     Copyright mcendu 2019.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

"""
AEAD wrappers.
"""
import struct
from typing import NoReturn

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305

from librvlt.base.callbacks import AEAlgorithm


@AEAlgorithm.register(29)
class ChaCha20Poly1305(AEAlgorithm):
    """
    ChaCha20Poly1305 wrapper. Almost exactly what is defined in RFC 8439
    <https://tools.ietf.org/html/rfc8439>.
    """
    text_len: int = 0
    aad_len: int = 0

    def __init__(self, key: bytes, iv: bytes,
                 decrypt: bool = False, aad: bytes = b''):
        super().__init__(decrypt)
        self.cipher = Cipher(
            ChaCha20(key, iv), None, default_backend()
        ).encryptor()
        # Initialize MAC key
        mac_key = self.cipher.update(bytes(64))[:32]
        self.mac = Poly1305(
            mac_key
            & b'\xff\xff\xff\x0f\xfc\xff\xff\x0f'
              b'\xfc\xff\xff\x0f\xfc\xff\xff\x0f'
              b'\xff\xff\xff\xff\xff\xff\xff\xff'
              b'\xff\xff\xff\xff\xff\xff\xff\xff'
        )
        # if AAD exists, update AAD to self.mac
        if not aad:
            return
        self.aad_len = len(aad)
        pad1_len = 16 - (self.aad_len % 16) % 16
        self.mac.update(aad + bytes(pad1_len))

    def encrypt(self, b: bytes) -> bytes:
        c_text = self.cipher.update(b)
        self.text_len += len(c_text)
        self.mac.update(c_text)
        return c_text

    def decrypt(self, b: bytes) -> bytes:
        self.text_len += len(b)
        self.mac.update(b)
        return self.cipher.update(b)

    def read(self, b: bytes) -> NoReturn:
        self.mac.update(b)

    def __end_auth_msg(self):
        pad2_len = 16 - (self.text_len % 16) % 16
        self.mac.update(pad2_len)
        self.mac.update(struct.pack(b'<Q<Q',
                                    self.aad_len, self.text_len))

    def tag(self) -> bytes:
        self.__end_auth_msg()
        return self.mac.finalize()

    def verify(self, b: bytes) -> bool:
        self.__end_auth_msg()
        return self.mac.verify(b)
