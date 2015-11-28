"""
Miner driver for the 21 mining shield on the Raspberry Pi 2.
"""

import minerhal.libminerhal as libminerhal
import minerhal
from . import miner
byref = libminerhal.ffi.addressof


class RPi2Miner(miner.Miner):
    """21 miner shield on Raspberry Pi 2 driver."""

    def __init__(self):
        """Open the 21 miner shield on Raspberry Pi 2 driver.

        Raises:
            miner.MinerOpenError: if open failed

        """
        self._miner = libminerhal.lib.rpi2miner
        self._board = libminerhal.ffi.cast("rpi2miner_board_t *", self._miner.get_board())
        self._config = libminerhal.ffi.cast("rpi2miner_config_t *", self._miner.get_config())

        self._minerchips = [minerhal.drivers.EESCS21.from_c_obj(minerchip) for minerchip in self._board.minerchips]
        self._pol = minerhal.drivers.PV3012.from_c_obj(self._board.pol)
        self._clkgen = minerhal.drivers.SI5351.from_c_obj(self._board.clkgen)
        self._adc = minerhal.drivers.PAC1710.from_c_obj(self._board.adc)

        self._open()

    @property
    def minerchips(self):
        """list: List of minerhal.driver.EESCS21 driver objects."""
        return self._minerchips

    @property
    def pol(self):
        """minerhal.drivers.PV3012: PV3012 point-of-load driver object."""
        return self._pol

    @property
    def clkgen(self):
        """minerhal.drivers.SI5351: SI5351 clock generator driver object."""
        return self._clkgen

    @property
    def adc(self):
        """minerhal.drivers.PAC1710: PAC1710 sense current adc driver object."""
        return self._adc

    def test_bist(self):
        """Run the BIST component of the miner self-test.

        Returns:
            tuple: Tuple of four bitmasks representing passing cores for each minerchip, respectively. Unsigned 64-bit integers

        Raises:
            miner.MinerIOError: if an input/output error occurs

        """
        bist_results = libminerhal.ffi.new("uint64_t [%d]" % libminerhal.lib.RPI2MINER_NUM_MINERCHIPS)
        ret = libminerhal.lib.rpi2miner_test_bist(byref(bist_results))
        self._assert_ret(ret)
        return tuple(bist_results)

    def test_work_builder(self):
        """Run the workbuilder component of the miner self-test.

        Returns:
            tuple: Tuple of four bitmasks representing passing cores for each minerchip, respectively. Unsigned 64-bit integers

        Raises:
            miner.MinerIOError: if an input/output error occurs

        """
        work_builder_results = libminerhal.ffi.new("uint64_t [%d]" % libminerhal.lib.RPI2MINER_NUM_MINERCHIPS)
        ret = libminerhal.lib.rpi2miner_test_work_builder(byref(work_builder_results))
        self._assert_ret(ret)
        return tuple(work_builder_results)

    def led_on(self):
        """Turn on the green LED on the miner shield.

        Raises:
            miner.MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.rpi2miner_led_on()
        self._assert_ret(ret)

    def led_off(self):
        """Turn off the green LED on the miner shield.

        Raises:
            miner.MinerIOError: if an input/output error occurs

        """
        ret = libminerhal.lib.rpi2miner_led_off()
        self._assert_ret(ret)

    def set_hashing_frequency(self, frequency):
        """Set a custom hashing frequency (100MHz-400MHz). Takes effect
        immediately, but also re-initializes the minerchips, so a new work load
        is required to resume hashing.

        Args:
            frequency (float): hashing frequency in Hertz

        Raises:
            miner.MinerArgumentError: if frequency is out of bounds
            miner.MinerIOError: if an input/output error occurs
            miner.MinerInitializationError: if a minerchip PLL does not lock

        """
        ret = libminerhal.lib.rpi2miner_set_hashing_frequency(frequency)
        self._assert_ret(ret)

    def get_hashing_frequency(self):
        """Get the current hashing frequency.

        Returns:
            float: Current hashing frequency in Hertz.
        """
        frequency = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.rpi2miner_get_hashing_frequency(frequency)
        self._assert_ret(ret)
        return frequency[0]

    def set_hashing_voltage(self, voltage):
        """Set a custom hashing voltage (0.45V-0.85V). Takes effect at next
        work load.

        Args:
            voltage (float): hashing voltage in Volts

        Raises:
            miner.MinerArgumentError: if voltage is out of bounds

        """
        ret = libminerhal.lib.rpi2miner_set_hashing_voltage(voltage)
        self._assert_ret(ret)

    def get_hashing_voltage(self):
        """Get the current hashing voltage.

        Returns:
            float: Current hashing voltage in Volts.
        """
        voltage = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.rpi2miner_get_hashing_voltage(voltage)
        self._assert_ret(ret)
        return voltage[0]

    def is_calibrated(self):
        """Checks whether the miner shield has been calibrated.

        Returns:
            bool: True if the miner shield has been calibrated, otherwise false.

        Raises:
            miner.MinerIOError: if an input/output error occurs
        """
        _is_calibrated = libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.rpi2miner_is_calibrated(_is_calibrated)
        self._assert_ret(ret)
        return bool(_is_calibrated[0])

    def _calibrate_hashing_voltage(self, store_config=False):
        """Finds the optimal hashing voltage for the miner shield.

        If store_config is True, then the calculated hashing voltage is stored in non-volatile memory (nvm) located in the pol.

        Note:
            The pol nvm is a one time program and can be filled if called multiple times. Proceed with
            caution when using this function!

        Args:
            store_config (bool): Store the configuration after calibration.

        Returns:
            float: Optimal hashing voltage in volts found during the calibration process.

        Raises:
            miner.MinerIOError: if an input/output error occurs
        """
        hashing_voltage = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.rpi2miner_calibrate_hashing_voltage(store_config, hashing_voltage)
        self._assert_ret(ret)
        return hashing_voltage[0]
