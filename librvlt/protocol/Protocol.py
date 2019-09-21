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
import struct
from abc import ABC, abstractmethod

from .base.Factory import Factory


class Protocol(ABC, Factory):
    """
    A protocol request/response.
    """

    'Constants.'

    MAGIC = 0x72766c74  # b'rvlt'

    'Abstract methods.'

    @classmethod
    @abstractmethod
    def _decode(cls, b):
        """
        Decode a protocol request/response to internal form.
        :param b: The protocol request/response.
        :return: The decoded object.
        """

    @abstractmethod
    def _encode(self) -> bytes:
        """
        Encode a protocol request/response.
        :return: The protocol request/response.
        """
        return struct.pack('>L>L', self.MAGIC, self.type_id)
