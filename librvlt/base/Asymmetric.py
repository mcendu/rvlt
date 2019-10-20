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
    KeyExchange, SignatureAlgorithm
)


class X25519(KeyExchange):
    """
    Wrapper for the X25519 key exchange.
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

    def serialize(self) -> bytes:
        key = self.key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw,
            NoEncryption()
        )
        return key
