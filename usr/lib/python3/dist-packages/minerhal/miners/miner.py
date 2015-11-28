"""
Miner driver base class.
"""

import minerhal.libminerhal as libminerhal
import collections
import codecs
byref = libminerhal.ffi.addressof

# Miner Errors


class MinerError(IOError):
    """Base exception class for Miner errors."""
    pass


class MinerOpenError(MinerError):
    """Open error."""
    pass


class MinerIOError(MinerError):
    """Input/output error."""
    pass


class MinerArgumentError(MinerError):
    """Invalid argument error."""
    pass


class MinerInitializationError(MinerError):
    """Initialization error."""
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


class MinerWork:
    """Abstract base class for Miner work structures."""

    def __init__(self):
        raise TypeError("This class can only be constructed from derived classes.")


class MinerSimpleWork(MinerWork):
    """Simple Miner work structure.

    This structure contains the work state needed for mining the last 16 bytes
    of the 80-byte Bitcoin block header. This includes the SHA-256 midstate of
    the first 512-bits of block header, the 32-bit remainder of the merkle
    root, 32-bit timestamp, 32-bit compact target, 32-bit nonce, and the 32-bit
    compact target for solution comparison (for pool mining).

    """

    def __init__(self, midstate, merkle_lsw, bits, timestamp, bits_comp):
        """Create an instance of MinerSimpleWork.

        Args:
            midstate (bytes, list, tuple): SHA-256 midstate of the first 512-bits of the block header. Internal byte order
            merkle_lsw (bytes, list, tuple): Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order
            bits (int): Compact difficulty target in block header
            timestamp (int): Timestamp in block header
            bits_comp (int): Compact difficulty target used to find solution

        Returns:
            MinerSimpleWork: Instance of MinerSimpleWork

        """
        self._work = libminerhal.ffi.new("miner_work_t *")[0]
        self._work.type = libminerhal.lib.WORK_TYPE_SIMPLE
        self.midstate = midstate
        self.merkle_lsw = merkle_lsw
        self.bits = bits
        self.timestamp = timestamp
        self.bits_comp = bits_comp

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of MinerSimpleWork that wraps a miner_work_t CFFI object.

        Args:
            c_obj (<cdata 'struct miner_work'>): The miner_work_t CFFI object to wrap

        Returns:
            MinerSimpleWork: Instance of MinerSimpleWork wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct miner_work'>
            ValueError: if `c_obj` work type is not `WORK_TYPE_SIMPLE`

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_work_t"):
            raise TypeError("c_obj type should be <cdata 'struct miner_work'>.")
        if c_obj.type != libminerhal.lib.WORK_TYPE_SIMPLE:
            raise ValueError("work type should be WORK_TYPE_SIMPLE.")

        self = cls.__new__(cls)
        self._work = c_obj

    @property
    def midstate(self):
        """bytes: SHA-256 midstate of the first 512-bits of the block header. 32 bytes, internal byte order."""
        return bytes(self._work.data.simple.midstate)

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
        self._work.data.simple.midstate = bytes(midstate)

    @property
    def merkle_lsw(self):
        """bytes: Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order."""
        return bytes(self._work.data.simple.merkle_lsw)

    @merkle_lsw.setter
    def merkle_lsw(self, merkle_lsw):
        """Least significant word (last four bytes) of merkle root in block header. 4 bytes, internal byte order.

        Args:
            merkle_lsw (bytes, tuple, list): Merkle root least significant word. 4 bytes internal, byte order

        Raises:
            TypeError: if `merkle_lsw` type is invalid
            ValueError: if `merkle_lsw` length is invalid

        """
        _validate_bytes(merkle_lsw, libminerhal.lib.MERKLE_LSW_LEN, "merkle_lsw")
        self._work.data.simple.merkle_lsw = bytes(merkle_lsw)

    @property
    def bits(self):
        """int: Compact difficulty target in block header. Unsigned 32-bit integer."""
        return self._work.data.simple.bits

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
        self._work.data.simple.bits = bits

    @property
    def timestamp(self):
        """int: Timestamp in block header. Unsigned 32-bit integer."""
        return self._work.data.simple.timestamp

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
        self._work.data.simple.timestamp = timestamp

    @property
    def bits_comp(self):
        """int: Compact difficulty target used to find solution. Unsigned 32-bit integer."""
        return self._work.data.simple.bits_comp

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
        self._work.data.simple.bits_comp = bits_comp

    def __str__(self):
        """Get string representation of simple work."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Midstate", codecs.encode(self.midstate, 'hex_codec').decode())
        ret_str += _str_format_field("Merkle LSW", codecs.encode(self.merkle_lsw, 'hex_codec').decode())
        ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
        ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
        ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
        return ret_str


class MinerBitshareWork(MinerWork):
    """Bitshare Miner work structure.

    This structure contains the work state needed for mining with a 21 Bitshare
    ASIC, which appends an output to a hardcoded wallet address to the coinbase
    transaction on-chip. This mechanism requires the chip to build the coinbase
    transaction on-chip, which means it needs additional state compared to the
    MinerSimpleWork structure.

    In particular, the Bitshare Miner work structure is composed of three
    sub-structures:

        - MinerBitshareWork.BlockHeader: the block header to mine, minus the
          merkle root, which will be computed on-chip.
        - MinerBitshareWork.MerkleEdge: the edge of transaction double hashes
          needed to compute the block header merkle root, after the Coinbase
          transaction has been built on-chip.
        - MinerBitshareWork.Coinbase: the information needed to build the
          Coinbase transaction with the append additional output.

    """

    class BlockHeader:
        """Bitshare Block Header structure."""

        def __init__(self, version, prev_block_hash, bits, timestamp, bits_comp):
            """Create an instance of BlockHeader.

            Args:
                version (int): Version
                prev_block_hash (bytes, tuple, list): Previous block header double hash. 32 bytes, internal byte order
                bits (int): Compact difficulty target
                timestamp (int): Timestamp
                bits_comp (int): Compact difficulty target used to find solution

            Returns:
                BlockHeader: Instance of BlockHeader

            """
            self._block_header = libminerhal.ffi.new("miner_work_bitshare_block_header_t *")[0]
            self.version = version
            self.prev_block_hash = prev_block_hash
            self.bits = bits
            self.timestamp = timestamp
            self.bits_comp = bits_comp

        @classmethod
        def from_c_obj(cls, c_obj):
            """Create an instance of BlockHeader that wraps a miner_work_bitshare_block_header_t CFFI object.

            Args:
                c_obj (<cdata 'struct miner_work_bitshare_block_header'>): The miner_work_bitshare_block_header_t CFFI object to wrap

            Returns:
                BlockHeader: Instance of BlockHeader wrapping the CFFI object

            Raises:
                TypeError: if `c_obj` type is not <cdata 'struct miner_work_bitshare_block_header'>

            """
            if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_work_bitshare_block_header_t"):
                raise TypeError("c_obj type should be <cdata 'struct miner_work_bitshare_block_header'>.")

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
            ret_str += _str_format_field("Version", self.version)
            ret_str += _str_format_field("Prev Block Hash", codecs.encode(self.prev_block_hash, 'hex_codec').decode())
            ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
            ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
            ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
            return ret_str

    class MerkleEdge:
        """Bitshare Merkle Edge structure."""

        def __init__(self, roots):
            """Create an instance of MerkleEdge.

            Args:
                roots (list): list of SHA-256 transaction double hashes representing the merkle edge. Each of type bytes. 32 bytes, internal byte order

            Returns:
                MerkleEdge: Instance of MerkleEdge

            Raises:
                TypeError: if `roots` type or double hash in `roots` type is invalid
                ValueError: if double hash in `roots` length is invalid

            """
            if not isinstance(roots, list):
                raise TypeError("roots type should be list.")
            for root in roots:
                _validate_bytes(root, libminerhal.lib.SHA256_MIDSTATE_LEN, "root element")

            self.txn_dhashes = libminerhal.ffi.new("miner_transaction_hash_t []", len(roots))
            self._merkle_edge = libminerhal.ffi.new("miner_work_bitshare_merkle_edge_t *")[0]
            self._merkle_edge.txn_dhashes = self.txn_dhashes
            self._merkle_edge.num_txn_dhash = len(roots)

            for i in range(len(roots)):
                self.txn_dhashes[i].dhash = bytes(roots[i])

        @classmethod
        def from_c_obj(cls, c_obj):
            """Create an instance of MerkleEdge that wraps a miner_work_bitshare_merkle_edge_t CFFI object.

            Args:
                c_obj (<cdata 'struct miner_work_bitshare_merkle_edge'>): The miner_work_bitshare_merkle_edge_t CFFI object to wrap

            Returns:
                MerkleEdge: Instance of MerkleEdge wrapping the CFFI object

            Raises:
                TypeError: if `c_obj` type is not <cdata 'struct miner_work_bitshare_merkle_edge'>

            """
            if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_work_bitshare_merkle_edge_t"):
                raise TypeError("c_obj type should be <cdata 'struct miner_work_bitshare_merkle_edge'>.")

            self = cls.__new__(cls)
            self._merkle_edge = c_obj
            return self

        def __len__(self):
            """Get length of merkle edge.

            Returns:
                int: Length of merkle edge

            """
            return self._merkle_edge.num_txn_dhash

        def __getitem__(self, index):
            """Get transaction double hash from merkle edge.

            Args:
                index (int): Index of transaction double hash

            Returns:
                bytes: Transaction double hash. 32 bytes, internal byte order

            """
            return bytes(self.txn_dhashes[index].dhash)

        def __setitem__(self, index, value):
            """Set transaction double hash in merkle edge.

            Args:
                index (int): Index of transaction double hash
                value (bytes, tuple, list): Transaction double hash. 32 bytes, internal byte order

            Raises:
                TypeError: if `value` type is invalid
                ValueError: if `value` length is invalid

            """
            _validate_bytes(value, libminerhal.lib.SHA256_HASH_LEN, "value")
            self.txn_dhashes[index].dhash = bytes(value)

        def __str__(self):
            """Get string representation of merkle edge."""
            ret_str = self.__class__.__name__ + "\n"
            ret_str += _str_format_field("Transaction Hashes", "Count: {}".format(len(self)))
            for i in range(len(self)):
                ret_str += _str_format_field("", codecs.encode(self[i], 'hex_codec').decode())
            return ret_str

    class Coinbase:
        """Bitshare Coinbase structure."""

        def __init__(self, midstate, wallet_id, block_height, lock_time, data_length):
            """Create an instance of Coinbase.

            Args:
                prev_midstate (bytes, tuple, list): SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output. 32 bytes, internal byte order.
                wallet_id (int): Wallet address index for additional appended output by the chip
                block_height (int): Current block height (for reward calculation)
                lock_time (int): Coinbase transaction lock time
                data_length (int): Length of coinbase transaction in bits, up to last output

            Returns:
                Coinbase: Instance of Coinbase

            """
            self._coinbase = libminerhal.ffi.new("miner_work_bitshare_coinbase_t *")[0]
            self.midstate = midstate
            self.wallet_id = wallet_id
            self.block_height = block_height
            self.lock_time = lock_time
            self.data_length = data_length

        @classmethod
        def from_c_obj(cls, c_obj):
            """Create an instance of Coinbase that wraps a miner_work_bitshare_coinbase_t CFFI object.

            Args:
                c_obj (<cdata 'struct miner_work_bitshare_coinbase'>): The miner_work_bitshare_coinbase_t CFFI object to wrap

            Returns:
                Coinbase: Instance of Coinbase wrapping the CFFI object

            Raises:
                TypeError: if `c_obj` type is not <cdata 'struct miner_work_bitshare_coinbase'>

            """
            if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_work_bitshare_coinbase_t"):
                raise TypeError("c_obj type should be <cdata 'struct miner_work_bitshare_coinbase'>.")

            self = cls.__new__(cls)
            self._coinbase = c_obj
            return self

        @property
        def midstate(self):
            """bytes: SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output. 32 bytes, internal byte order."""
            return bytes(self._coinbase.midstate)

        @midstate.setter
        def midstate(self, midstate):
            """SHA-256 midstate of 512-bit padded coinbase transaction, up to the last output.

            Args:
                prev_midstate (bytes, tuple, list): SHA-256 midstate. 32 bytes, internal byte order

            Raises:
                TypeError: if `prev_midstate` type is invalid
                ValueError: if `prev_midstate` length is invalid

            """
            _validate_bytes(midstate, libminerhal.lib.SHA256_MIDSTATE_LEN, "midstate")
            self._coinbase.midstate = bytes(midstate)

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
                TypeError: if `walle_idt` type is invalid
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
            ret_str += _str_format_field("Midstate", codecs.encode(self.midstate, 'hex_codec').decode())
            ret_str += _str_format_field("Wallet ID", "0x{:08x}".format(self.wallet_id))
            ret_str += _str_format_field("Block Height", "{}".format(self.block_height))
            ret_str += _str_format_field("Lock Time", "{}".format(self.lock_time))
            ret_str += _str_format_field("Data Length", "{}".format(self.data_length))
            return ret_str

    def __init__(self, block_header, merkle_edge, coinbase):
        """Create an instance of MinerBishareWork from Bitshare block header, merkle edge, and coinbase structures

        Args:
            block_header (MinerBitshareWork.BlockHeader): Block header
            merkle_edge (MinerBitshareWork.MerkleEdge): Merkle edge
            coinbase (MinerBitshareWork.Coinbase): Coinbase

        Returns:
            MinerBitshareWork: Instance of MinerBitshareWork

        Raises:
            TypeError: if `block_header`, `merkle_edge`, or `coinbase` types are invalid

        """
        if not isinstance(block_header, MinerBitshareWork.BlockHeader):
            raise TypeError("block_header type should be MinerBitshareWork.BlockHeader.")
        if not isinstance(merkle_edge, MinerBitshareWork.MerkleEdge):
            raise TypeError("merkle_edge type should be MinerBitshareWork.MerkleEdge.")
        if not isinstance(coinbase, MinerBitshareWork.Coinbase):
            raise TypeError("merkle_edge type should be MinerBitshareWork.Coinbase.")

        self._work = libminerhal.ffi.new("miner_work_t *")[0]
        self._work.type = libminerhal.lib.WORK_TYPE_BITSHARE
        self._work.data.bitshare.block_header = block_header._block_header
        self._work.data.bitshare.merkle_edge = merkle_edge._merkle_edge
        self._work.data.bitshare.coinbase = coinbase._coinbase

        self._block_header = MinerBitshareWork.BlockHeader.from_c_obj(self._work.data.bitshare.block_header)
        self._merkle_edge = MinerBitshareWork.MerkleEdge.from_c_obj(self._work.data.bitshare.merkle_edge)
        self._coinbase = MinerBitshareWork.Coinbase.from_c_obj(self._work.data.bitshare.coinbase)

    @property
    def block_header(self):
        """MinerBitshareWork.BlockHeader: Block Header structure."""
        return self._block_header

    @property
    def merkle_edge(self):
        """MinerBitshareWork.MerkleEdge: Merkle Edge structure."""
        return self._merkle_edge

    @property
    def coinbase(self):
        """MinerBitshareWork.Coinbase: Coinbase structure."""
        return self._coinbase

    def __str__(self):
        """Get string representation of Miner Bitshare work."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += str(self.block_header) + "\n"
        ret_str += str(self.merkle_edge) + "\n"
        ret_str += str(self.coinbase)
        return ret_str


class MinerSolution(object):
    """Miner solution structure.

    This structure contains a solution to a Bitcoin block header. It includes
    a minimal version of the block header itself (midstate, merkle root least
    significant word, timestamp, compact difficulty target, nonce), the compact
    difficulty target the solution meets, and metadata with the origin of the
    solution and the timestamp of when it was found.

    """

    def __init__(self):
        raise TypeError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of MinerSolution that wraps a miner_solution_t CFFI object.

        Args:
            c_obj (<cdata 'struct miner_solution'>): The miner_solution_t CFFI object to wrap

        Returns:
            MinerSolution: Instance of MinerSolution wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct miner_solution'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_solution_t"):
            raise TypeError("c_obj type should be <cdata 'struct miner_solution'>.")

        self = cls.__new__(cls)
        self._solution = c_obj
        return self

    @property
    def worker(self):
        """int: Worker index that found this solution. Unsigned 32-bit integer."""
        return self._solution.worker

    @property
    def core_id(self):
        """int: Core index that found this solution. Unsigned 32-bit integer."""
        return self._solution.core_id

    @property
    def found_timestamp(self):
        """float: Timestamp of solution relative to work load, in seconds."""
        return self._solution.found_timestamp

    @property
    def midstate(self):
        """bytes: SHA-256 midstate of the first 512-bits of the block header. 32 bytes, internal byte order."""
        return bytes(self._solution.midstate)

    @property
    def merkle_lsw(self):
        """bytes: Least significant word (last four bytes) of merkle root in block header. 32 bytes, internal byte order."""
        return bytes(self._solution.merkle_lsw)

    @property
    def bits(self):
        """int: Compact difficulty target in solution block header. Unsigned 32-bit integer."""
        return self._solution.bits

    @property
    def timestamp(self):
        """int: Timestamp in solution block header. Unsigned 32-bit integer."""
        return self._solution.timestamp

    @property
    def nonce(self):
        """int: Nonce in solution block header. Unsigned 32-bit integer."""
        return self._solution.nonce

    @property
    def bits_comp(self):
        """int: Compact difficulty target used to find solution. Unsigned 32-bit integer."""
        return self._solution.bits_comp

    def __str__(self):
        """Get string representation of Miner solution."""
        ret_str = self.__class__.__name__ + "\n"
        ret_str += _str_format_field("Worker", "{}".format(self.worker))
        ret_str += _str_format_field("Core ID", "{}".format(self.core_id))
        ret_str += _str_format_field("Found Timestamp", "{:.2f} s".format(self.found_timestamp))
        ret_str += _str_format_field("Midstate", codecs.encode(self.midstate, 'hex_codec').decode())
        ret_str += _str_format_field("Merkle LSW", codecs.encode(self.merkle_lsw, 'hex_codec').decode())
        ret_str += _str_format_field("Bits", "0x{:08x}".format(self.bits))
        ret_str += _str_format_field("Timestamp", "0x{:08x}".format(self.timestamp))
        ret_str += _str_format_field("Nonce", "0x{:08x}".format(self.nonce))
        ret_str += _str_format_field("Bits Comp", "0x{:08x}".format(self.bits_comp))
        return ret_str


# Miner Object

class Miner(object):
    """Abstract base class for Miner drivers."""

    _ERROR_CODE_TO_EXCEPTIONS = {
        libminerhal.lib.MINER_ERROR_OPEN: MinerOpenError,
        libminerhal.lib.MINER_ERROR_IO: MinerIOError,
        libminerhal.lib.MINER_ERROR_ARGS: MinerArgumentError,
        libminerhal.lib.MINER_ERROR_INIT: MinerInitializationError,
    }

    def __init__(self):
        raise TypeError("This class can only be constructed from derived classes.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of Miner that wraps a miner_driver_t CFFI object.

        Args:
            c_obj (<cdata 'struct miner_driver'>): The miner_driver_t CFFI object to wrap

        Returns:
            Miner: Instance of Miner wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct miner_driver'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("miner_driver_t"):
            raise TypeError("c_obj type should be <cdata 'struct miner_driver'>.")

        self = cls.__new__(cls)
        self._miner = c_obj
        return self

    def _assert_ret(self, ret):
        errmsg = libminerhal.ffi.string(libminerhal.lib.miner_errmsg(byref(self._miner))).decode()
        if ret in Miner._ERROR_CODE_TO_EXCEPTIONS:
            raise Miner._ERROR_CODE_TO_EXCEPTIONS[ret](errmsg)
        elif ret != 0:
            raise Exception("Unknown return code! \n\tret {0} - errmsg {1}".format(ret, errmsg))

    def _open(self):
        """Open.

        Raises:
            MinerOpenError: if open fails

        """
        ret = libminerhal.lib.miner_open(byref(self._miner))
        self._assert_ret(ret)

    def close(self):
        """Close.

        Raises:
            MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.miner_close(byref(self._miner))
        self._assert_ret(ret)

    def reset(self):
        """Reset to powered off state.

        This must be followed by a call to `initialize()` to restore the miner
        to operating condition.

        Raises:
            MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.miner_reset(byref(self._miner))
        self._assert_ret(ret)

    def initialize(self):
        """Initialize.

        Raises:
            MinerInitializationError: if initialization fails
            MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.miner_initialize(byref(self._miner))
        self._assert_ret(ret)

    def idle(self):
        """Idle. Stops hashing on all work.

        Raises:
            MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.miner_idle(byref(self._miner))
        self._assert_ret(ret)

    def selftest(self):
        """Self-test.

        Returns:
            dict: Dictionary with "passed": <bool>, "report": <str>

        Raises:
            MinerIOError: if an input/output error occurs

        """
        passed = libminerhal.ffi.new("bool *")
        report = libminerhal.ffi.new("const char **")
        ret = libminerhal.lib.miner_selftest(byref(self._miner), passed, report)
        self._assert_ret(ret)
        return {"passed": bool(passed[0]), "report": libminerhal.ffi.string(report[0]).decode()}

    def supported_work(self):
        """Get list of supported work classes, e.g. MinerSimpleWork,
        MinerBitshareWork.

        Returns:
            list: List of MinerWork derived classes supported by this miner

        """
        supported = libminerhal.lib.miner_supported_work(byref(self._miner))

        # Return list of supported MinerWork classes
        supported_list = []
        if supported & (1 << libminerhal.lib.WORK_TYPE_SIMPLE):
            supported_list.append(MinerSimpleWork)
        if supported & (1 << libminerhal.lib.WORK_TYPE_BITSHARE):
            supported_list.append(MinerBitshareWork)
        return supported_list

    def num_workers(self):
        """Get number of independent workers.

        Returns:
            int: Number of independent workers

        """
        return libminerhal.lib.miner_num_workers(byref(self._miner))

    def load_work(self, works):
        """Load work.

        Arguments:
            works (list): List of MinerWork objects to load

        Raises:
            TypeError: if work type is invalid
            MinerArgumentError: if `works` length is out of bounds or work type is unsupported
            MinerIOError: if an input/output error occurs

        """
        for work in works:
            if not isinstance(work, MinerWork):
                raise TypeError("work type should be MinerWork. type(work) = {}".format(type(work)))

        # Build contiguous array of work
        c_works = libminerhal.ffi.new("miner_work_t []", len(works))
        for i, work in enumerate(works):
            c_works[i] = work._work

        ret = libminerhal.lib.miner_load_work(byref(self._miner), c_works, len(works))
        self._assert_ret(ret)

    def poll_found(self, timeout_ms=None):
        """Poll for a solution. `timeout_ms` defaults to None for a blocking poll.

        Arguments:
            timeout_ms (None, int): Timeout in milliseconds

        Returns:
            bool: True if miner found a solution, False if it timed out

        Raises:
            TypeError: if `timeout_ms` type is invalid
            MinerIOError: if an input/output error occurs

        """
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise TypeError("timeout_ms type should be None or int.")

        if timeout_ms is None:
            timeout_ms = -1

        found = libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.miner_poll_found(byref(self._miner), found, timeout_ms)
        self._assert_ret(ret)
        return bool(found[0])

    def read_solution(self):
        """Read a solution.

        Returns:
            MinerSolution or None: Solution or None, if no solution has been found

        Raises:
            MinerIOError: if an input/output error occurs

        """
        found = libminerhal.ffi.new("bool *")
        solution = libminerhal.ffi.new("miner_solution_t *")
        ret = libminerhal.lib.miner_read_solution(byref(self._miner), solution, found)
        self._assert_ret(ret)

        if bool(found[0]):
            return MinerSolution.from_c_obj(solution[0])
        else:
            return None

    def read_stats(self):
        """Read statistics.

        Returns:
            collections.OrderedDict: Ordered dictionary of statistics

        """
        num_stats = libminerhal.lib.miner_num_stats(byref(self._miner))
        c_stats = libminerhal.ffi.new("miner_stat_t []", num_stats)
        ret = libminerhal.lib.miner_read_stats(byref(self._miner), c_stats)
        self._assert_ret(ret)

        stats = collections.OrderedDict()
        for c_stat in c_stats:
            name = libminerhal.ffi.string(c_stat.name).decode()
            if c_stat.type == libminerhal.lib.STAT_TYPE_BOOL:
                stats[name] = bool(c_stat.value.b_value)
            elif c_stat.type == libminerhal.lib.STAT_TYPE_UINT:
                stats[name] = c_stat.value.u_value
            elif c_stat.type == libminerhal.lib.STAT_TYPE_FLOAT:
                stats[name] = c_stat.value.f_value
            elif c_stat.type == libminerhal.lib.STAT_TYPE_STRING:
                stats[name] = libminerhal.ffi.string(c_stat.value.s_value).decode()
            elif c_stat.type == libminerhal.lib.STAT_TYPE_ERROR:
                stats[name] = Exception(libminerhal.ffi.string(c_stat.value.e_value).decode())

        return stats

    def _get_config(self):
        """<cdata 'void *'>: CFFI void pointer to configuration structure."""
        return libminerhal.lib.miner_get_config(byref(self._miner))

    def _get_board(self):
        """<cdata 'void *'>: CFFI void pointer to board structure."""
        return libminerhal.lib.miner_get_board(byref(self._miner))

    @property
    def name(self):
        """str: Name of miner driver."""
        return libminerhal.ffi.string(libminerhal.lib.miner_name(byref(self._miner))).decode()

