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
Callback object interface spec.
"""
from abc import ABC, abstractmethod
from typing import NoReturn, Optional, Union

from librvlt.base import Factory


class AEAlgorithm(ABC, Factory):
    """
    Wrapper for an AE/AEAD algorithm.

    AE stands for "Authenticated encryption", a method that transmits
    data securely while providing authenticity (data is provably not
    corrupted or modified in transmission).
    """

    def __init__(
            self, key: bytes, iv: bytes,
    ):
        pass

    def update(self, b: bytes):
        """
        Process data passed in. On __init__, this function is replaced
        with any of the below three functions.
        :param b: Plaintext.
        :return: Ciphertext as bytes.
        """

    @abstractmethod
    def encrypt(self, b: bytes) -> bytes:
        """Encrypt b and return the ciphertext."""

    def decrypt(self, b: bytes) -> bytes:
        """Do the inverse of encrypt."""
        return self.encrypt(b)

    @abstractmethod
    def read(self, b: bytes) -> NoReturn:
        """Update the MAC without decrypting."""

    @abstractmethod
    def finalize(self) -> bytes:
        """
        Finalize the algorithm.

        Upon call, sets self.tag to the computed tag and returns the
        last block + pad (empty string if no padding required).
        """

    @abstractmethod
    def verify(self, b: bytes) -> bool:
        """Compare an authentication tag against another."""


class KeyExchange(ABC, Factory):
    """
    Wrapper for a key exchange/pub-key encryption algorithm.
    """


class SignatureSystem(ABC, Factory):
    """
    Wrapper for a signature algorithm.
    """
