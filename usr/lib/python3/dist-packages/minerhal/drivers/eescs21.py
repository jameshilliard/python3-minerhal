"""
EESCS21 minerchip driver, data structures, and errors.
"""

import minerhal.libminerhal as libminerhal
import codecs
byref = libminerhal.ffi.addressof

# Errors


class EESCS21Error(IOError):
    """Base exception class for EESCS21 errors."""
    pass


class EESCS21ArgumentError(EESCS21Error):
    """Invalid argument error."""
    pass


class EESCS21IOError(EESCS21Error):
    """Input/output error."""
    pass


class EESCS21DetectError(EESCS21Error):
    """Chip ID detect failed error."""
    pass


class EESCS21UnlockError(EESCS21Error):
    """Unlock failed error."""
    pass


class EESCS21PllConfigError(EESCS21Error):
    """PLL configuration failed error."""
    pass


# Helper functions to validate arguments


def _validate_uint8(obj, name):
    if not isinstance(obj, int):
        raise TypeError("{} type should int.".format(name))
    if obj.bit_length() > 8:
        raise ValueError("{} out of bounds (8-bits).".format(name))


def _validate_uint32(obj, name):
    if not isinstance(obj, int):
        raise TypeError("{} type should int.".format(name))
    if obj.bit_length() > 32:
        raise ValueError("{} out of bounds (32-bits).".format(name))


def _validate_bytes(obj, length, name):
    if not isinstance(obj, bytes) and not isinstance(obj, list) and not isinstance(obj, tuple):
        raise TypeError("{} type should be bytes, list of bytes, or tuple of bytes.".format(name))
    if len(obj) != length:
        raise ValueError("{} length should be {}.".format(name, length))


def _str_format_field(name, value, indent=4, width=20):
    return "{indent}{:<{width}}{}\n".format(name, value, indent=" "*indent, width=width)


# EESCS21 Data Structures


class EESCS21OutputData(object):
    """EESCS21 solution structure."""

    def __init__(self):
        raise TypeError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of EESCS21OutputData that wraps a eescs21_output_data_t CFFI object.

        Args:
            c_obj (<cdata 'struct eescs21_output_data'>): The eescs21_output_data_t CFFI object to wrap

        Returns:
            EESCS21OutputData: Instance of EESCS21OutputData wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct eescs21_output_data'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("eescs21_output_data_t"):
            raise TypeError("c_obj type should be <cdata 'struct eescs21_output_data'>.")

        self = cls.__new__(cls)
        self._output_data = c_obj
        return self

    @property
    def midstate(self):
        """bytes: SHA-256 midstate of the first 512-bits of the block header. 32 bytes, internal byte order."""
        return bytes(self._output_data.midstate)

    @property
    def merkle_lsw(self):
        """bytes: Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order."""
        return bytes(self._output_data.merkle_lsw)

    @property
    def bits(self):
        """int: Compact difficulty target in solution block header. Unsigned 32-bit integer."""
        return self._output_data.bits

    @property
    def input_timestamp(self):
        """int: Timestamp specified in work. Unsigned 32-bit integer."""
        return self._output_data.input_timestamp

    @property
    def bits_comp(self):
        """int: Compact difficulty target used to find solution. Unsigned 32-bit integer."""
        return self._output_data.bits_comp

    @property
    def timestamp(self):
        """int: Timestamp in solution block header. Unsigned 32-bit integer."""
        return self._output_data.timestamp

    @property
    def nonce(self):
        """int: Nonce in solution block header. Unsigned 32-bit integer."""
        return self._output_data.nonce

    @property
    def hashgroup_address(self):
        """int: Hashgroup that produced this solution. Unsigned integer, 0-3."""
        return self._output_data.hashgroup_address

    @property
    def core_address(self):
        """int: Core within hashgroup that produced this solution. Unsigned integer, 0-15."""
        return self._output_data.core_address

    def __str__(self):
        """Get string representation of block header solution."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Midstate", codecs.encode(self.midstate, 'hex_codec').decode())
        ret_str += _str_format_field("Merkle LSW", codecs.encode(self.merkle_lsw, 'hex_codec').decode())
        ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
        ret_str += _str_format_field("Input Timestamp", "0x{:08x}".format(self.input_timestamp))
        ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
        ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
        ret_str += _str_format_field("Nonce", "0x{:08x}".format(self.nonce))
        ret_str += _str_format_field("Hashgroup Address", "0x{:02x}".format(self.hashgroup_address))
        ret_str += _str_format_field("Core Address", "0x{:02x}".format(self.core_address))
        return ret_str


class EESCS21Work:
    """EESCS21 simple work structure, for BIST and non-Bitshare work loading."""

    def __init__(self, midstate, merkle_lsw, bits, timestamp, bits_comp):
        """Create an instance of EESCS21Work.

        Args:
            midstate (bytes, list, tuple): SHA-256 midstate of the first 512-bits of the block header. 32 bytes, internal byte order
            merkle_lsw (bytes, list, tuple): Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order
            bits (int): Compact difficulty target in block header
            timestamp (int): Timestamp in block header
            bits_comp (int): Compact difficulty target used to find solution

        Returns:
            EESCS21Work: Instance of EESCS21Work

        """
        self._work = libminerhal.ffi.new("eescs21_work_t *")[0]
        self.midstate = midstate
        self.merkle_lsw = merkle_lsw
        self.bits = bits
        self.timestamp = timestamp
        self.bits_comp = bits_comp

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of EESCS21Work that wraps a eescs21_work_t CFFI object.

        Args:
            c_obj (<cdata 'struct eescs21_work'>): The eescs21_work_t CFFI object to wrap

        Returns:
            EESCS21Work: Instance of EESCS21Work wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct eescs21_work'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("eescs21_work_t"):
            raise TypeError("c_obj type should be <cdata 'struct eescs21_work'>.")

        self = cls.__new__(cls)
        self._work = c_obj
        return self

    @property
    def midstate(self):
        """bytes: SHA-256 midstate of the first 512-bits of the block header. 32 bytes, internal byte order."""
        return bytes(self._work.midstate)

    @midstate.setter
    def midstate(self, midstate):
        """SHA-256 midstate of the first 512-bits of the block header.

        Args:
            midstate (bytes, tuple, list): SHA-256 midstate. 32 bytes, internal byte order

        Raises:
            TypeError: if `midstate` type is invalid
            ValueError: if `midstate` length is invalid

        """
        _validate_bytes(midstate, libminerhal.lib.SHA256_MIDSTATE_LEN, "midstate")
        self._work.midstate = bytes(midstate)

    @property
    def merkle_lsw(self):
        """bytes: Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order."""
        return bytes(self._work.merkle_lsw)

    @merkle_lsw.setter
    def merkle_lsw(self, merkle_lsw):
        """Least significant word (last four bytes) of merkle root in block header.

        Args:
            merkle_lsw (bytes, tuple, list): Merkle root least significant word. 4 bytes, internal byte order

        Raises:
            TypeError: if `merkle_lsw` type is invalid
            ValueError: if `merkle_lsw` length is invalid

        """
        _validate_bytes(merkle_lsw, libminerhal.lib.MERKLE_LSW_LEN, "merkle_lsw")
        self._work.merkle_lsw = bytes(merkle_lsw)

    @property
    def bits(self):
        """int: Compact difficulty target in block header. Unsigned 32-bit integer."""
        return self._work.bits

    @bits.setter
    def bits(self, bits):
        """Compact difficulty target in block header.

        Args:
            bits (int): Compact difficulty target. Unsigned 32-bit integer

        Raises:
            TypeError: if `bits` type is invalid
            ValueError: if `bits` value is out of bounds

        """
        _validate_uint32(bits, "bits")
        self._work.bits = bits

    @property
    def timestamp(self):
        """int: Timestamp in block header. Unsigned 32-bit integer."""
        return self._work.timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        """Timestamp in block header.

        Args:
            timestamp (int): Timestamp. Unsigned 32-bit integer

        Raises:
            TypeError: if `timestamp` type is invalid
            ValueError: if `timestamp` value is out of bounds

        """
        _validate_uint32(timestamp, "timestamp")
        self._work.timestamp = timestamp

    @property
    def bits_comp(self):
        """int: Compact difficulty target used to find solution. Unsigned 32-bit integer."""
        return self._work.bits_comp

    @bits_comp.setter
    def bits_comp(self, bits_comp):
        """Compact difficulty target used to find solution.

        Args:
            bits_comp (int): Compact difficulty target. Unsigned 32-bit integer

        Raises:
            TypeError: if `bits_comp` type is invalid
            ValueError: if `bits_comp` value is out of bounds

        """
        _validate_uint32(bits_comp, "bits_comp")
        self._work.bits_comp = bits_comp

    def __str__(self):
        """Get string representation of simple work."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Midstate", codecs.encode(self.midstate, 'hex_codec').decode())
        ret_str += _str_format_field("Merkle LSW", codecs.encode(self.merkle_lsw, 'hex_codec').decode())
        ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
        ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
        ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
        return ret_str


class EESCS21BlockHeader:
    """EESCS21 block header structure, for Bitshare work loading."""

    def __init__(self, version, prev_block_hash, bits, timestamp, bits_comp):
        """Create an instance of EESCS21BlockHeader.

        Args:
            version (int): Version
            prev_block_hash (bytes, tuple, list): Previous block header double hash. 32 bytes, internal byte order
            bits (int): Compact difficulty target
            timestamp (int): Timestamp
            bits_comp (int): Compact difficulty target used to find solution

        Returns:
            EESCS21BlockHeader: Instance of EESCS21BlockHeader

        """
        self._block_header = libminerhal.ffi.new("eescs21_block_header_t *")[0]
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.bits = bits
        self.timestamp = timestamp
        self.bits_comp = bits_comp

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of EESCS21BlockHeader that wraps a eescs21_block_header_t CFFI object.

        Args:
            c_obj (<cdata 'struct eescs21_block_header'>): The eescs21_block_header_t CFFI object to wrap

        Returns:
            EESCS21BlockHeader: Instance of EESCS21BlockHeader wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct eescs21_block_header'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("eescs21_block_header_t"):
            raise TypeError("c_obj type should be <cdata 'struct eescs21_block_header'>.")

        self = cls.__new__(cls)
        self._block_header = c_obj
        return self

    @property
    def version(self):
        """int: Block header version. Unsigned 32-bit integer."""
        return self._block_header.version

    @version.setter
    def version(self, version):
        """Block header version.

        Args:
            version (int): Block header version. Unsigned 32-bit integer

        Raises:
            TypeError: if `version` type is invalid
            ValueError: if `version` value is out of bounds

        """
        _validate_uint32(version, "version")
        self._block_header.version = version

    @property
    def prev_block_hash(self):
        """bytes: Previous block header double hash. 32-bytes, internal byte order."""
        return bytes(self._block_header.prev_block_hash)

    @prev_block_hash.setter
    def prev_block_hash(self, prev_block_hash):
        """Previous block header double hash.

        Args:
            prev_block_hash (bytes, tuple, list): Previous block double hash. 32-bytes, internal byte order

        Raises:
            TypeError: if `prev_block_hash` type is invalid
            ValueError: if `prev_block_hash` length is invalid

        """
        _validate_bytes(prev_block_hash, libminerhal.lib.SHA256_HASH_LEN, "prev_block_hash")
        self._block_header.prev_block_hash = bytes(prev_block_hash)

    @property
    def bits(self):
        """int: Compact difficulty target. Unsigned 32-bit integer."""
        return self._block_header.bits

    @bits.setter
    def bits(self, bits):
        """Compact difficulty target.

        Args:
            bits (int): Compact difficulty target. Unsigned 32-bit integer

        Raises:
            TypeError: if `bits` type is invalid
            ValueError: if `bits` is out of bounds

        """
        _validate_uint32(bits, "bits")
        self._block_header.bits = bits

    @property
    def timestamp(self):
        """int: Timestamp. Unsigned 32-bit integer."""
        return self._block_header.timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        """Timestamp.

        Args:
            timestamp (int): Timestamp. Unsigned 32-bit integer

        Raises:
            TypeError: if `timestamp` type is invalid
            ValueError: if `timestamp` is out of bounds

        """
        _validate_uint32(timestamp, "timestamp")
        self._block_header.timestamp = timestamp

    @property
    def bits_comp(self):
        """int: Compact difficulty target used to find solution. Unsigned 32-bit integer."""
        return self._block_header.bits_comp

    @bits_comp.setter
    def bits_comp(self, bits_comp):
        """Compact difficulty target used to find solution.

        Args:
            bits_comp (int): Compact difficulty target. Unsigned 32-bit integer

        Raises:
            TypeError: if `bits_comp` type is invalid
            ValueError: if `bits_comp` is out of bounds

        """
        _validate_uint32(bits_comp, "bits_comp")
        self._block_header.bits_comp = bits_comp

    def __str__(self):
        """Get string representation of block header."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Version", "0x{:08x}".format(self.version))
        ret_str += _str_format_field("Prev Block Hash", codecs.encode(self.prev_block_hash, 'hex_codec').decode())
        ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
        ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
        ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
        return ret_str


class EESCS21Coinbase:
    """EESCS21 coinbase structure, for Bitshare work loading."""

    def __init__(self, prev_midstate, wallet_id, block_height, lock_time, data_length):
        """Create an instance of EESCS21Coinbase.

        Args:
            prev_midstate (bytes, tuple, list): SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output. 32 bytes, internal byte order
            wallet_id (int): Wallet address index for additional appended output by the EESCS21
            block_height (int): Current block height (for reward calculation)
            lock_time (int): Coinbase transaction lock time
            data_length (int): Length of 512-bit padded coinbase transaction in bits, up to last output

        Returns:
            EESCS21Coinbase: Instance of EESCS21Coinbase

        """
        self._coinbase = libminerhal.ffi.new("eescs21_coinbase_t *")[0]
        self.prev_midstate = prev_midstate
        self.wallet_id = wallet_id
        self.block_height = block_height
        self.lock_time = lock_time
        self.data_length = data_length

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of EESCS21Coinbase that wraps a eescs21_coinbase_t CFFI object.

        Args:
            c_obj (<cdata 'struct eescs21_coinbase'>): The eescs21_coinbase_t CFFI object to wrap

        Returns:
            EESCS21Coinbase: Instance of EESCS21Coinbase wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct eescs21_coinbase'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("eescs21_coinbase_t"):
            raise TypeError("c_obj type should be <cdata 'struct eescs21_coinbase'>.")

        self = cls.__new__(cls)
        self._block_header = c_obj
        return self

    @property
    def prev_midstate(self):
        """bytes: SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output. 32 bytes, internal byte order."""
        return bytes(self._coinbase.prev_midstate)

    @prev_midstate.setter
    def prev_midstate(self, prev_midstate):
        """SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output.

        Args:
            prev_midstate (bytes, tuple, list): SHA-256 midstate. 32 bytes, internal byte order

        Raises:
            TypeError: if `prev_midstate` type is invalid
            ValueError: if `prev_midstate` length is invalid

        """
        _validate_bytes(prev_midstate, libminerhal.lib.SHA256_MIDSTATE_LEN, "prev_midstate")
        self._coinbase.prev_midstate = bytes(prev_midstate)

    @property
    def wallet_id(self):
        """int: Wallet address index for additional appended output by the EESCS21. Unsigned 32-bit integer."""
        return self._coinbase.wallet_id

    @wallet_id.setter
    def wallet_id(self, wallet_id):
        """Wallet address index for additional appended output by the EESCS21.

        Args:
            wallet_id (int): Wallet address index. Unsigned 32-bit integer

        Raises:
            TypeError: if `walle_id` type is invalid
            ValueError: if `wallet_id` is out of bounds

        """
        _validate_uint32(wallet_id, "wallet_id")
        self._coinbase.wallet_id = wallet_id

    @property
    def block_height(self):
        """int: Current block height (for reward calculation). Unsigned 32-bit integer."""
        return self._coinbase.block_height

    @block_height.setter
    def block_height(self, block_height):
        """Current block height (for reward calculation).

        Args:
            block_height (int): Current block height. Unsigned 32-bit integer

        Raises:
            TypeError: if `block_height` type is invalid
            ValueError: if `block_height` is out of bounds

        """
        _validate_uint32(block_height, "block_height")
        self._coinbase.block_height = block_height

    @property
    def lock_time(self):
        """int: Coinbase transaction lock time."""
        return self._coinbase.lock_time

    @lock_time.setter
    def lock_time(self, lock_time):
        """Coinbase transaction lock time.

        Args:
            lock_time (int): Transaction lock time. Unsigned 32-bit integer

        Raises:
            TypeError: if `lock_time` type is invalid
            ValueError: if `lock_time` is out of bounds

        """
        _validate_uint32(lock_time, "lock_time")
        self._coinbase.lock_time = lock_time

    @property
    def data_length(self):
        """int: Length of 512-bit padded coinbase transaction in bits, up to last output. Unsigned 32-bit integer."""
        return self._coinbase.data_length

    @data_length.setter
    def data_length(self, data_length):
        """Length of 512-bit padded coinbase transaction in bits, up to last output.

        Args:
            data_length (int): Length. Unsigned 32-bit integer

        Raises:
            TypeError: if `data_length` type is invalid
            ValueError: if `data_length` is out of bounds

        """
        _validate_uint32(data_length, "data_length")
        self._coinbase.data_length = data_length

    def __str__(self):
        """Get string representation of coinbase."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Prev Midstate", codecs.encode(self.prev_midstate, 'hex_codec').decode())
        ret_str += _str_format_field("Wallet ID", "0x{:08x}".format(self.wallet_id))
        ret_str += _str_format_field("Block Height", "{}".format(self.block_height))
        ret_str += _str_format_field("Lock Time", "{}".format(self.lock_time))
        ret_str += _str_format_field("Data Length", "{}".format(self.data_length))
        return ret_str

# EESCS21 Object


class EESCS21:
    """EESCS21 minerchip driver."""

    _ERROR_CODE_TO_EXCEPTIONS = {
        libminerhal.lib.EESCS21_ERROR_ARGS: EESCS21ArgumentError,
        libminerhal.lib.EESCS21_ERROR_IO: EESCS21IOError,
        libminerhal.lib.EESCS21_ERROR_DETECT: EESCS21DetectError,
        libminerhal.lib.EESCS21_ERROR_UNLOCK: EESCS21UnlockError,
        libminerhal.lib.EESCS21_ERROR_PLL_CONFIG: EESCS21PllConfigError,
    }

    def __init__(self):
        raise TypeError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of EESCS21 that wraps a eescs21_t CFFI object.

        Args:
            c_obj (<cdata 'struct eescs21'>): The eescs21_t CFFI object to wrap

        Returns:
            EESCS21: Instance of EESCS21 wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct eescs21'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("eescs21_t"):
            raise TypeError("c_obj type should be <cdata 'struct eescs21'>.")

        self = cls.__new__(cls)
        self._minerchip = c_obj
        return self

    def _assert_ret(self, ret):
        errmsg = libminerhal.ffi.string(libminerhal.lib.eescs21_errmsg(byref(self._minerchip))).decode()
        if ret in EESCS21._ERROR_CODE_TO_EXCEPTIONS:
            raise EESCS21._ERROR_CODE_TO_EXCEPTIONS[ret](errmsg)
        elif ret != 0:
            raise Exception("Unknown return code! \n\tret {0} - errmsg {1}".format(ret, errmsg))

    def init(self, freq):
        """Initialize.

        Args:
            freq (float): Frequency to set the internal PLL to in Hertz

        Raises:
            EESCS21DetectError: if minerchip is not detected
            EESCS21UnlockError: if minerchip unlock (V2 only) fails
            EESCS21IOError: if an input/output error occurs
            EESCS21PllConfigError: if PLL configuration fails

        """
        ret = libminerhal.lib.eescs21_init(byref(self._minerchip, freq))
        self._assert_ret(ret)

    def hard_reset(self):
        """Hard-reset.

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.eescs21_hard_reset(byref(self._minerchip))
        self._assert_ret(ret)

    def idle(self, broadcast=False):
        """Idle instruction: stop hashing by freezing nonce counter on all cores.

        Args:
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.eescs21_idle(byref(self._minerchip), broadcast)
        self._assert_ret(ret)

    def disable_all(self, broadcast=False):
        """Disable all instruction: stop hashing by clock gating all cores.

        Args:
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.eescs21_disable_all(byref(self._minerchip), broadcast)
        self._assert_ret(ret)

    def disable_core(self, hashgroup, core):
        """Disable core instruction: stop core from hashing by clock gating.

        Args:
            hashgroup (int): Hashgroup index core resides in. Unsigned integer, 0-3
            core (int): Core index in hashgroup. Unsigned integer, 0-15

        Raises:
            TypeError: if `hashgroup` type or `core` type is invalid
            ValueError: if `hashgroup` or `core` are out of bounds
            EESCS21IOError: if an input/output error occurs

        """
        _validate_uint8(hashgroup, "hashgroup")
        _validate_uint8(core, "core")
        ret = libminerhal.lib.eescs21_disable_core(byref(self._minerchip), hashgroup, core)
        self._assert_ret(ret)

    def chip_id(self):
        """Chip ID instruction: read chip ID.

        Returns:
            bytes: chip ID. 16 bytes

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        chip_id = libminerhal.ffi.new("eescs21_chip_id_t *")
        ret = libminerhal.lib.eescs21_chip_id(byref(self._minerchip), chip_id)
        self._assert_ret(ret)
        return bytes(chip_id.data)

    def pll_config(self, frequency, bypass=False):
        """PLL configuration instruction: configure chip frequency.

        Args:
            frequency (float, int): Frequency in Hertz
            bypass (bool): Bypass PLL and use reference frequency

        Raises:
            EESCS21PllConfigError: if PLL configuration fails
            EESCS21IOError: if an input/output error occurs

        """
        if not isinstance(frequency, float) and not isinstance(frequency, int):
            raise TypeError("frequency type should be float or int.")
        ret = libminerhal.lib.eescs21_pll_config(byref(self._minerchip), float(frequency), bypass)
        self._assert_ret(ret)

    def get_frequency(self):
        """Get configured chip frequency.

        Returns:
            float: Frequency in Hertz

        """
        frequency = libminerhal.lib.eescs21_get_frequency(byref(self._minerchip))
        return frequency

    def bist_start(self, work, broadcast=False):
        """BIST start instruction: start BIST with provided work.

        The EESCS21 built-in self-test (BIST) increments the nonce and lower
        4-bits of the timestamp of the block header in the provided work until
        a solution is found meeting the bits_comp target is found.

        Args:
            work (EESCS21Work): Work to load for BIST
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        if not isinstance(work, EESCS21Work):
            raise TypeError("work type should be EESCS21Work. type(work) = {}".format(type(work)))

        ret = libminerhal.lib.eescs21_bist_start(byref(self._minerchip), byref(work._work), broadcast)
        self._assert_ret(ret)

    def bist_out(self):
        """BIST out instruction: get results of BIST.

        Returns:
            int: Bitmask of core that have found a solution to BIST work. Unsigned 64-bit integer

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        bist_results = libminerhal.ffi.new("uint64_t *")
        ret = libminerhal.lib.eescs21_bist_out(byref(self._minerchip), bist_results)
        self._assert_ret(ret)
        return bist_results[0]

    def load_data(self, work, hashgroup):
        """Load data instruction: load work onto the specified hashgroup.

        This instruction is for V2 EESCS21 only.

        Args:
            work (EESCS21Work): Work to load for hashing
            hashgroup (int): Hashgroup index to load work for. Unsigned integer, 0-3

        Raises:
            TypeError: if `hashgroup` type is invalid
            ValueError: if `hashgroup` is out of bounds
            EESCS21IOError: if an input/output error occurs

        """
        if not isinstance(work, EESCS21Work):
            raise TypeError("work type should be EESCS21Work. type(work) = {}".format(type(work)))
        _validate_uint8(hashgroup, "hashgroup")

        ret = libminerhal.lib.eescs21_load_data(byref(self._minerchip), byref(work._work), hashgroup)
        self._assert_ret(ret)

    def reset_txn_data(self, broadcast=False):
        """Reset transaction data instruction: reset the transaction double hash table.

        Args:
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.eescs21_reset_txn_data(byref(self._minerchip), broadcast)
        self._assert_ret(ret)

    def load_block_header(self, block_header, broadcast=False):
        """Load block header instruction: load the block header.

        Args:
            block_header (EESCS21BlockHeader): Block header to load
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            EESCS21IOError: if an input/output error occurs


        """
        if not isinstance(block_header, EESCS21BlockHeader):
            raise TypeError("block_header type should be EESCS21BlockHeader! type(block_header) = {}".format(type(block_header)))

        ret = libminerhal.lib.eescs21_load_block_header(byref(self._minerchip), byref(block_header._block_header), broadcast)
        self._assert_ret(ret)

    def load_txn_dhash(self, dhash, broadcast=False):
        """Load transaction double hash instruction: load one transaction double hash into the transaction table.

        Args:
            dhash (bytes, list, tuple): Transaction double hash. 32 bytes, internal byte order
            broadcast (bool): Broadcast this instruction to all dies on bus

        Raises:
            TypeError: if `dhash` type is invalid
            ValueError: if `dhash` length is invalid
            EESCS21IOError: if an input/output error occurs

        """
        _validate_bytes(dhash, libminerhal.lib.SHA256_HASH_LEN, "dhash")

        c_dhash = libminerhal.ffi.new("eescs21_dhash_t *")
        c_dhash.dhash = bytes(dhash)
        ret = libminerhal.lib.eescs21_load_txn_dhash(byref(self._minerchip), c_dhash, broadcast)
        self._assert_ret(ret)

    def load_coinbase(self, coinbase, hashgroup):
        """Load coinbase instruction: load coinbase structure for specified hashgroup and start hashing.

        Args:
            coinbase (EESCS21Coinbase): Coinbase to load for hashing
            hashgroup (int): Hashgroup index to load work for. Unsigned integer, 0-3

        Raises:
            TypeError: if `hashgroup` type is invalid
            ValueError: if `hashgroup` is out of bounds
            EESCS21IOError: if an input/output error occurs

        """
        if not isinstance(coinbase, EESCS21Coinbase):
            raise TypeError("coinbase type should be EESCS21Coinbase! type(coinbase) = {}".format(type(coinbase)))
        _validate_uint8(hashgroup, "hashgroup")

        ret = libminerhal.lib.eescs21_load_coinbase(byref(self._minerchip), byref(coinbase._coinbase), hashgroup)
        self._assert_ret(ret)

    def output_data(self):
        """Output data instruction: read block header solution.

        Returns:
            EESCS21OutputData: Solution to block header

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        output_data = libminerhal.ffi.new("eescs21_output_data_t *")
        ret = libminerhal.lib.eescs21_output_data(byref(self._minerchip), output_data)
        self._assert_ret(ret)
        return EESCS21OutputData.from_c_obj(output_data[0])

    def send_data_from_core(self, hashgroup, core):
        """Send data from core instruction: read current state of a specific core.

        The solution returned may not be a valid solution to the block header.

        Args:
            hashgroup (int): Hashgroup index core resides in. Unsigned integer, 0-3
            core (int): Core index in hashgroup. Unsigned integer, 0-15

        Returns:
            EESCS21OuptutData: Solution (possible invalid) to block header

        Raises:
            TypeError: if `hashgroup` type or `core` type is invalid
            ValueError: if `hashgroup` or `core` are out of bounds
            EESCS21IOError: if an input/output error occurs

        """
        _validate_uint8(hashgroup, "hashgroup")
        _validate_uint8(core, "core")
        output_data = libminerhal.ffi.new("eescs21_output_data_t *")
        ret = libminerhal.lib.eescs21_send_data_from_core(byref(self._minerchip), hashgroup, core, output_data)
        self._assert_ret(ret)
        return EESCS21OutputData.from_c_obj(output_data[0])

    def status(self):
        """Status instruction: read chip PLL locked and found status.

        Returns:
            dict: Dictionary with 'pll_locked': <bool> and 'found': <bool> statuses

        Raises:
            EESCS21IOError: if an input/output error occurs

        """
        status = libminerhal.ffi.new("eescs21_status_t *")
        ret = libminerhal.lib.eescs21_status(byref(self._minerchip), status)
        self._assert_ret(ret)
        return {'found': bool(status.found), 'pll_locked': bool(status.pll_locked)}

