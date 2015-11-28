# Drivers and Driver Structures
import minerhal.drivers

# Miner Errors
from .miners.miner import MinerError
from .miners.miner import MinerOpenError
from .miners.miner import MinerIOError
from .miners.miner import MinerArgumentError
from .miners.miner import MinerInitializationError

# Miner Structures
from .miners.miner import MinerSimpleWork
from .miners.miner import MinerBitshareWork
from .miners.miner import MinerSolution

# Miners
from .miners.rpi2miner import RPi2Miner
from .miners.cpuminer import CpuMiner

# Version
import minerhal.libminerhal

# Strip "v" prefix in version string, e.g. "v0.1.0-g12345af" -> "0.1.0-g12345af"
__version__ = minerhal.libminerhal.ffi.string(minerhal.libminerhal.lib.MINERHAL_VERSION_STR).decode()[1:]
"Module version string."

version = (minerhal.libminerhal.lib.MINERHAL_VERSION.major,
           minerhal.libminerhal.lib.MINERHAL_VERSION.minor,
           minerhal.libminerhal.lib.MINERHAL_VERSION.patch)
"Module version tuple."

