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
the Registration class.
"""
from hashlib import blake2b
from os import urandom

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
    (Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _gen_login_key(password: bytes, identity: bytes):
    """
    Derives a key from a password and identifier. The key is used to decrypt
    (also unlock) the secret key of a user.
    """
    kdf_input = blake2b(password).digest() ^ blake2b(identity).digest()
    kdf = Scrypt(b'', 32, 16384, 8, 1, default_backend())
    return kdf.derive(kdf_input)


class Registration:
    def __init__(self):
        # Hash of private signature key in unencrypted form.
        self.identity: bytes = b''
        # Public signature key.
        self.sign_pub: bytes = b''
        # Private signature key, encrypted.
        self.sign_priv: bytes = b''
        # Nonce used in the encryption process.
        self.sign_iv: bytes = b''
        # Signature of private signature key.
        self.sign_sig: bytes = b''
        # Public encryption key.
        self.xchg_pub: bytes = b''
        # Private encryption key, encrypted.
        self.xchg_priv: bytes = b''
        # Nonce, ditto.
        self.xchg_iv: bytes = b''
        # Signature of private encryption key.
        self.xchg_sig: bytes = b''
        # Comment, can be used as username.
        self._comment: bytes = b''

    @property
    def sign(self):
        """Public signature key."""
        return self.sign_pub

    @property
    def xchg(self):
        """Public exchange key."""
        return self.xchg_pub

    @property
    def comment(self):
        """Comment of the account. Can be used as username."""
        return self._comment

    @classmethod
    def register(cls, password: bytes):
        """
        Generate a new account.
        :param password The password for encrypting the keys.
        :return a Registration.
        """
        reg = cls()
        # gen signature keypair
        sign_object = Ed25519PrivateKey.generate()
        reg.sign_pub = sign_object.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        sign = sign_object.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        reg.sign_sig = sign_object.sign(sign)
        # the private signature key's hash become the account's ID
        reg.identity = blake2b(sign).digest()
        # gen encryption keypair
        xchg_object = X25519PrivateKey.generate()
        reg.xchg_pub = xchg_object.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        xchg = xchg_object.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        reg.xchg_sig = sign_object.sign(xchg)
        # encrypt the private keys
        reg.set_passwd(sign, xchg, password)
        return reg

    def set_passwd(self, sign, xchg, password: bytes):
        """
        Set or replace the password by encrypting the private keys and storing
        the results.
        :param sign The signature key.
        :param xchg The encryption key.
        :param password The password for encrypting the keys.
        """
        # Verify key if key has been set
        if self.sign_priv:
            try:
                Ed25519PublicKey.from_public_bytes(self.sign).verify(
                    self.sign_sig, sign
                )
                Ed25519PublicKey.from_public_bytes(self.sign).verify(
                    self.xchg_sig, xchg
                )
            except cryptography.exceptions.InvalidSignature as e:
                raise SignatureMismatch(self.xchg_sig) from e
        # Do the actual encryption
        session = _gen_login_key(password, self.identity)
        self.sign_iv = urandom(16)
        context = Cipher(
            algorithms.ChaCha20(session, self.sign_iv), None, default_backend()
        ).encryptor()
        self.sign_priv = context.update(sign) + context.finalize()
        self.xchg_iv = urandom(16)
        context = Cipher(
            algorithms.ChaCha20(session, self.xchg_iv), None, default_backend()
        ).encryptor()  # Nonce reuse is considered bad practice
        self.xchg_priv = context.update(xchg) + context.finalize()

    def authenticate(self, password: bytes):
        """
        Decrypt the secret keys and test if it is identical to identity.
        :param password The password used to encrypt the keys.
        :return A tuple containing an X25519PrivateKey and an Ed25519PrivateKey,
        or None if the results does not match.
        """
        # Attempt to decrypt signature key
        session = _gen_login_key(password, self.identity)
        context = Cipher(
            algorithms.ChaCha20(session, self.sign_iv), None, default_backend()
        ).decryptor()
        sign = context.update(self.sign_priv) + context.finalize()
        # Verification
        identity = blake2b(sign).digest()
        if identity != self.identity:
            return None
        # Decrypt the encryption key
        context = Cipher(
            algorithms.ChaCha20(session, self.xchg_iv), None, default_backend()
        ).decryptor()
        xchg = context.update(self.xchg_priv) + context.finalize()
        return (
            Ed25519PrivateKey.from_private_bytes(sign),
            X25519PrivateKey.from_private_bytes(xchg)
        )

    def __dict__(self):
        return {
            "identity": self.identity,
            "sign": {
                "pub": self.sign,
                "sec": self.sign_priv,
                "sec_iv": self.sign_iv,
                "sig": self.sign_sig
            },
            "xchg": {
                "pub": self.xchg,
                "sec": self.xchg_priv,
                "sec_iv": self.xchg_iv,
                "sig": self.xchg_sig
            }
        }

    def __repr__(self):
        return f'<{type(self).__qualname__} identity={self.identity.hex()}>'


class SignatureMismatch(Exception):
    """
    Raised when using Registration.set_passwd would replace the user's private
    keys.
    """
    def __init__(self, expected: bytes):
        super(SignatureMismatch, self).__init__()
        self.args = (
            "{} expected".format(expected.hex()),
        )
