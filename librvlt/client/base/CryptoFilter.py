from abc import abstractmethod, ABCMeta
import errno
import io
from os import urandom
from typing import Union, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoFilter(metaclass=ABCMeta, io.BufferedIOBase):
    """
    A cryptographic process presented as a stream.
    """

    def __init__(self, raw: io.BufferedIOBase, buffer=4096):
        # raw stream
        self.raw = raw
        # internal buffer
        self._buffer = bytearray(buffer)
        self._buf_size = buffer
        self._pos = 0
        self._left = -1

    'Abstract methods.'

    @abstractmethod
    @property
    def finalized(self):
        """True if _pad has been called at least once."""

    @abstractmethod
    def _encrypt(self, b: bytearray) -> None:
        """
        Processes data passed in.
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
            size_real = min(size_real, self._left)
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
        self._pos = 0
        self._encrypt(self._buffer)
        self.raw.write(self._buffer[:size])

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

    'Overrides.'

    def read(self, size: Optional[int] = -1) -> bytes:
        if size < 0:
            return self._readall()
        b = bytearray(size)
        r = self.readinto(b)
        return bytes(b)[:r]

    def readinto(self, b) -> int:
        return self._non_tty_read(b)

    def readable(self) -> bool:
        return self.raw.readable()

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        if self.readable():
            return False  # prevent writing to protect from data corruption
        return self.raw.writable()

class AEADCryptoFilter(CryptoFilter):
    pass
