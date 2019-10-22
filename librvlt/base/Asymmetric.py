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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    NoEncryption, PublicFormat, PrivateFormat, Encoding
)

from librvlt.base.callbacks import (
    KeyExchange, SignatureAlgorithm, _PublicKey, _SignaturePublicKey
)


class X25519(KeyExchange):
    """
    Wrapper for Curve25519.
    """
    key: X25519PrivateKey

    @classmethod
    def generate(cls):
        key = cls()
        key.key = X25519PrivateKey.generate()
        return key

    @classmethod
    def import_private(cls, b):
        key = cls()
        key.key = X25519PrivateKey.from_private_bytes(b)
        return key

    def public(self):
        key = self._public_key_class()
        key.__key = self.key.public_key()
        return key

    def serialize(self) -> bytes:
        return self.key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw,
            NoEncryption()
        )

    def exchange(self, peer) -> bytes:
        return self.key.exchange(peer.key)


@X25519.public_key_class
class _X25519Pub(_PublicKey):
    __key: X25519PublicKey

    @property
    def key(self):
        return self.__key

    @classmethod
    def from_bytes(cls, b):
        key = cls()
        key.__key = X25519PublicKey.from_public_bytes(b)
        return key

    def serialize(self) -> bytes:
        return self.key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class Ed25519(SignatureAlgorithm):
    """
    Wrapper for Ed25519.
    """

    key: Ed25519PrivateKey

    @classmethod
    def generate(cls):
        key = cls()
        key.key = Ed25519PrivateKey.generate()
        return key

    @classmethod
    def import_private(cls, b):
        key = cls()
        key.key = Ed25519PrivateKey.from_private_bytes(b)
        return key

    def serialize(self) -> bytes:
        return self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                      NoEncryption())

    def public(self):
        key = self._public_key_class()
        key.__key = self.key.public_key()
        return key

    def sign(self, msg) -> bytes:
        return self.key.sign(msg)


class _Ed25519Pub(_SignaturePublicKey):
    __key: Ed25519PublicKey

    @property
    def key(self):
        return self.__key

    @classmethod
    def from_bytes(cls, b):
        key = cls()
        key.__key = Ed25519PublicKey.from_public_bytes(b)
        return key

    def serialize(self) -> bytes:
        return self.key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def verify(self, msg, signature) -> bool:
        try:
            self.key.verify(signature, msg)
            return True
        except InvalidSignature:
            return False
