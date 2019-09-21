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
from abc import abstractmethod, ABC
from typing import Union, Optional

from . import Factory


class CryptoFilter(ABC, Factory, io.BufferedIOBase):
    """
    A cryptographic process presented as a stream.
    """

    def __init__(self, raw: io.RawIOBase, buffer=io.DEFAULT_BUFFER_SIZE):
        # raw stream
        self.raw = raw
        # internal buffer
        self._buffer = bytearray(buffer)
        self._buf_size = buffer
        self._pos = 0
        self._left = -1

    'Abstract methods.'

    @abstractmethod
    def _encrypt(self, b: bytearray) -> None:
        """
        Processes data passed in.
        :param b: A bytes-like object.
        """

    @abstractmethod
    def _pad(self, b, size: int) -> int:
        """
        Pads the data passed in and finalize the cipher.
        In some cases e.g. in a ChaCha20-Poly1305 backed CryptoFilter, this
        method does nothing to b and instead appends data to the MAC input.
        :param b: A buffer to be modified, intended to be larger than size.
        :param size: The amount of data, i.e. no meaningful data exists after
        size.
        :return: size plus bytes padded, or 0 if no padding is required.
        """

    'Properties.'

    @property
    def block_size(self) -> int:
        """The cipher's block size, or 1 if stream cipher."""
        return 1

    'IO buffering.'

    def _fill_buffer(self) -> int:
        """
        Fill up and encrypt the buffer, setting _left upon EOF.
        :return: Amount of data filled into the buffer.
        """
        if self._left >= 0:
            return 0
        self._pos = 0
        r = self.raw.readinto(self._buffer)
        if r is None:
            raise BlockingIOError
        if r < self._buf_size:
            self._left = self._pad(self._buffer, r)
            return self._left
        self._encrypt(self._buffer)
        return self._buf_size

    def _advance_read_pos(self, b) -> int:
        """
        Advance self.pos while copying data into b. Stops upon end of buffer.
        :param b: A buffer for writing.
        :return: Amount of data written.
        """
        i_view = memoryview(self._buffer)[self._pos:]
        o_view = memoryview(b)
        size_real = len(b)
        # cut size to max affordable
        if self._left < 0:
            size_real = min(size_real, len(i_view))
        else:
            size_real = min(size_real, self._left - self._pos)
        o_view[:size_real] = i_view[:size_real]
        self._pos += size_real
        return size_real

    def _non_tty_read(self, b) -> int:
        """
        Read and encrypt data from a non-interactive stream.
        :param b: The buffer to receive data.
        :return: The amount of bytes read.
        """
        view = memoryview(b)
        # Gobble up the buffer.
        r = self._advance_read_pos(view)
        view = view[r:]
        left = len(view)
        if left <= 0:
            return len(b)
        while left >= self._buf_size and self._left < 0:
            # load and unload buffer
            r += self._fill_buffer()
            view[:self._buf_size] = self._buffer[:]
            # decrement
            view = view[self._buf_size:]
            left -= self._buf_size
        if left <= 0:
            return len(b)
        # eat remaining data
        self._fill_buffer()
        r += self._advance_read_pos(view)
        return r

    def _readinto1(self, b) -> int:
        """
        Implemented similar to read1 as in io.BufferedReader; If at least one
        byte is buffered, only buffered bytes are returned. Otherwise only one
        call is made to the raw stream.
        :return: Bytes read.
        """
        if self._pos != self._buf_size:
            return self._advance_read_pos(b)
        self._fill_buffer()
        return self._advance_read_pos(b)

    def _readall(self) -> bytes:
        """
        Read all the way to EOF and return the processed data.
        :return: A bytes containing the data processed.
        """
        # Gobble up the buffer
        b: bytes = self._buffer[self._pos:]
        self._pos = 0
        while self._fill_buffer() == self._buf_size:
            b += self._buffer
        # Eat bytes left
        b += self._buffer[:self._left]
        return b

    def _dump_buffer(self, size) -> None:
        """
        Dump contents of buffer to underlying stream.
        :param size:
        :return: None
        """
        dump_section = self._buffer[:size]
        self._pos = 0
        self._encrypt(dump_section)
        if self.raw.write(dump_section) is None:
            raise BlockingIOError

    def _advance_write_pos(self, b: memoryview) -> memoryview:
        """
        Advance self.pos while copying data from b. Stops upon end of buffer.
        :param b: A buffer's view to be read.
        :return: Data that are not copied into the buffer.
        """
        o_view = memoryview(self._buffer)[self._pos:]
        size_real = min(len(b), len(o_view))
        o_view[:size_real] = b[:size_real]
        self._pos += size_real
        return b[size_real:]

    def _buffered_write(self, b) -> int:
        """
        Write data to the buffer, encrypting and flushing upon filling up.
        :param b: A bytes-like object from which data is read.
        :return: Amount of bytes written.
        """
        view = memoryview(b)
        view = self._advance_write_pos(view)
        if len(view) <= 0:
            return len(b)
        while len(view) > self._buf_size:
            self._dump_buffer(self._buf_size)
            self._buffer[:] = view[:self._buf_size]
            view = view[self._buf_size:]
        if len(view) <= 0:
            return len(b)
        # Dump remaining data.
        self._advance_write_pos(view)
        return len(b)

    def _end_writing(self) -> None:
        """
        Finalize the writing session.
        """
        if self.writable():
            self._pos = self._pad(self._buffer, self._pos)
            self.raw.write(self._buffer[:self._pos])

    'Overrides.'

    def read(self, size: Optional[int] = -1) -> bytes:
        if size is None or size < 0:
            return self._readall()
        b = bytearray(size)
        r = self.readinto(b)
        return bytes(b)[:r]

    def readinto(self, b) -> int:
        return self._non_tty_read(b)

    def read1(self, size: int = -1) -> bytes:
        b = bytearray(min(size, self._buf_size))
        if size < 0:
            b = bytearray(self._buf_size)
        r = self.readinto1(b)
        return bytes(b)[:r]

    def readinto1(self, b) -> int:
        return self._readinto1(b)

    def readable(self) -> bool:
        return self.raw.readable()

    def write(self, b: Union[bytes, bytearray]) -> int:
        return self._buffered_write(b)

    def writable(self) -> bool:
        if self.readable():
            return False  # prevent writing to protect from data corruption
        return self.raw.writable()

    def seekable(self) -> bool:
        return False

    def flush(self) -> None:
        if self.writable():
            # round down operation
            size_to_flush = self._pos // self.block_size * self.block_size
            new_pos = self._pos % self.block_size
            # view of data section to be copied to start
            view = memoryview(self._buffer)[size_to_flush:]
            self._dump_buffer(size_to_flush)
            # copy un-dumped data to start
            self._buffer[:new_pos] = view[:new_pos]
            self._pos = new_pos

    def detach(self) -> io.RawIOBase:
        self._end_writing()
        raw = self.raw
        self.raw = None
        return raw

    def close(self) -> None:
        self._end_writing()
        self.raw = None
        # TODO: set closed to True on close()


class AEADCryptoFilter(ABC, CryptoFilter):
    pass
