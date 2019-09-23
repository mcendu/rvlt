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

from abc import ABC, abstractmethod

from librvlt.base import Factory
from librvlt.protocol import Protocol


@Protocol.register(0)
class Registration(ABC, Factory, Protocol):
    """
    Data that describes a user, consisting of their public keys and an
    identity derived from the public key.
    #
    Encrypted private keys can also be included in Registrations, but
    is not required to be uploaded.
    """

    @abstractmethod
    @property
    def sign(self):
        """The signing key of the user."""
        pass

    @abstractmethod
    @property
    def xchg(self):
        """The encryption key of the user."""
        pass

    @abstractmethod
    @classmethod
    def register(cls, password: bytes):
        """
        Generate a new account.
        :param password: The password for encrypting the keys.
        :return: a Registration.
        """
        pass

    @abstractmethod
    def authenticate(self, password: bytes):
        """
        Decrypt the secret keys and test if it is identical to identity.
        :param password The password used to encrypt the keys.
        :return A tuple containing an X25519PrivateKey and an Ed25519PrivateKey,
        or None if the results does not match.
        """
        pass

    @abstractmethod
    def set_password(self, sign, xchg, password: bytes):
        """
        Set or replace the password by encrypting the private keys and storing
        the results.
        :param sign: The signature key.
        :param xchg: The encryption key.
        :param password: The password for encrypting the keys.
        """
        pass
