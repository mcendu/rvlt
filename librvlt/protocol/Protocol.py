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
        Decode a protocol request/response. Only the header is processed
        as the remaining data would go to the body property.
        :param b: The header of the protocol request/response.
        :return: The decoded object.
        """

    @abstractmethod
    def _encode_header(self) -> bytes:
        """
        Encode the header of a protocol request/response.
        :return: The protocol request/response.
        """

    'Interface for subclasses.'

    @property
    def _master_header(self) -> bytes:
        return struct.pack('>L>L', self.MAGIC, self.type_id)

    @staticmethod
    def has_body(cls: type) -> type:
        """
        Declare that a Protocol subclass have a body.
        """
        ret = cls

        @property  # replacement function
        def body(self) -> Optional[BinaryIO]:
            """
            The body of the request/response.
            """
            return self._body
        ret.body = body
        return ret

    @property
    def body(self) -> Optional[BinaryIO]:
        """
        The body of the request/response.
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

    @classmethod
    def load(cls, file: BinaryIO):
        """
        Decode and return a Protocol object.
        """
        master = struct.unpack(b'>L>L', file.read(8))
        if master[0] != cls.MAGIC:
            raise ValueError(
                'Attempt to decode corrupted or non-RVLT data'
            )
        length = struct.unpack(b'>Q', file.read(8))  # header length
        header = file.read(length[0])
        concrete = cls.lookup(master[1])
        protocol = concrete._decode(header)
        protocol._body = file
        if protocol.body is None:
            file.close()
        return protocol
