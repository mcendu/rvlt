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
from typing import NoReturn, Union, Callable, Type

from librvlt.base import Factory


class AEAlgorithm(ABC, Factory):
    """
    Wrapper for an AE/AEAD algorithm.

    AE stands for "Authenticated encryption", a method that transmits
    data securely while providing authenticity (data is provably not
    corrupted or modified in transmission).
    """

    def __init__(self, decrypt: bool = False):
        if decrypt:
            self.update = self.decrypt
        else:
            self.update = self.encrypt

    def update(self, b: bytes):
        """
        Process data passed in. On __init__, this function is replaced
        with either of the below two functions.
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
    def tag(self) -> bytes:
        """
        Generate a MAC (message authentication code) from data fed.
        """

    @abstractmethod
    def verify(self, b: bytes) -> bool:
        """Compute a MAC and compare it against input."""


class _PublicKey(ABC):
    @property
    @abstractmethod
    def key(self):
        """
        The underlying object.
        """

    @classmethod
    @abstractmethod
    def from_bytes(cls, b):
        """
        Import a public key.
        """
        pass

    @abstractmethod
    def serialize(self) -> bytes:
        """
        Serialize the key.
        """


class Asymmetric(ABC):
    """
    Wrapper for an asymmetric cryptographic process.
    """

    _public_key_class: Type[_PublicKey]

    @classmethod
    def public_key_class(cls, target: Type[_PublicKey]) -> type:
        """
        Declare a class to be the public key part of this algorithm.
        """
        cls._public_key_class = target
        return target

    @classmethod
    @abstractmethod
    def generate(cls):
        """
        Generate a KeyExchange object.
        """
        pass

    @classmethod
    def import_public(cls, b) -> _PublicKey:
        """
        Import a public key.
        :param b: A bytes-like object.
        """
        return cls._public_key_class.from_bytes(b)

    @classmethod
    @abstractmethod
    def import_private(cls, b):
        """
        Import a private key.
        :param b: A bytes-like object.
        """

    @abstractmethod
    def public(self):
        """
        Generate the public key. The public key can be distributed free-
        ly without causing the private key to leak.
        """

    @abstractmethod
    def serialize(self) -> bytes:
        """
        Serialize the key.
        """


class SignatureAlgorithm(Asymmetric, ABC, Factory):
    def sign(self, msg) -> bytes:
        """
        Sign a message.
        :return: The signature.
        """


class _SignaturePublicKey(_PublicKey, ABC):
    @abstractmethod
    def verify(self, msg, signature) -> bool:
        """
        Verify the signature of a message.
        :return: True if signature matches, false otherwise.
        """


class KeyExchange(Asymmetric, ABC, Factory):
    @abstractmethod
    def exchange(self, peer: _PublicKey) -> bytes:
        """
        Create a shared secret from a private key and a public key.
        :return: The shared secret.
        """
