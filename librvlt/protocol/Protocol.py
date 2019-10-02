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
import io
import struct
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO

from librvlt.base import Factory


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
    def _encode_header(self) -> bytes:
        """
        Encode the header of a protocol request/response.
        :return: The protocol request/response.
        """
        return struct.pack('>L>L', self.MAGIC, self.type_id)

    @property
    def body(self) -> Optional[BinaryIO]:
        """
        The body of the request/response. This part should only be used
        for those that can have significant size.
        """
        return None

    'Public interface.'

    def dump(self, file: BinaryIO):
        """
        Serialize the request/response to a file object.
        """
        # header
        file.write(self._encode_header())
        if self.body is None:
            return
        # body
        while self.body.closed:
            file.write(self.body.read(64))

    @staticmethod
    def load():
        pass
