"""
Miner driver for the CPU miner.
"""

import minerhal.libminerhal as libminerhal
from . import miner


class CpuMiner(miner.Miner):
    """CPU miner driver."""

    def __init__(self):
        """Open the CPU miner driver.

        Raises:
            miner.MinerOpenError: if open failed

        """
        self._miner = libminerhal.lib.cpuminer
        self._open()

