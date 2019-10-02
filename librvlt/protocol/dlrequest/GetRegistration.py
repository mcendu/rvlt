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

from librvlt.protocol import Protocol


@Protocol.register(0x1001)
class GetRegistration(Protocol):
    """
    Requests the server to download a registration.
    """

    def _encode_header(self) -> bytes: return b''.join((
            struct.pack(b'>H', len(self.identity)),
            self.identity
        ))

    @classmethod
    def _decode(cls, b):
        ln: int = struct.unpack(b'>H', b)[0]
        return cls(b[2:][:ln])

    _identity: bytes = b''

    @property
    def identity(self):
        """The identity of the reg to be downloaded."""
        return self._identity

    def __init__(self, identity=b''):
        self._identity = identity
