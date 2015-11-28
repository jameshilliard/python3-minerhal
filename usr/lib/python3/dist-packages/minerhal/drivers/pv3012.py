"""
PV3012 point-of-load driver and errors.
"""

import minerhal.libminerhal as libminerhal
byref = libminerhal.ffi.addressof

# Errors


class PV3012Error(IOError):
    """Base exception class for PV3012 errors."""
    pass


class PV3012ArgumentError(PV3012Error):
    """Invalid argument error."""
    pass


class PV3012IOError(PV3012Error):
    """Input/output error."""
    pass


class PV3012ExternalError(PV3012Error):
    """External error."""
    pass


class PV3012UnsupportedError(PV3012Error):
    """Unsupported function error."""
    pass

# PV3012 Object


class PV3012(object):
    """PV3012 point-of-load driver."""

    _ERROR_CODE_TO_EXCEPTIONS = {
        libminerhal.lib.PV3012_ERROR_IO: PV3012IOError,
        libminerhal.lib.PV3012_ERROR_ARGS: PV3012ArgumentError,
        libminerhal.lib.PV3012_ERROR_EXTERNAL: PV3012ExternalError,
        libminerhal.lib.PV3012_ERROR_UNSUPPORTED: PV3012UnsupportedError
    }

    def __init__(self):
        raise TypeError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of PV3012 that wraps a pv3012_t CFFI object.

        Args:
            c_obj (<cdata 'struct pv3012'>): The pv3012_t CFFI object to wrap

        Returns:
            PV3012: Instance of PV3012 wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct pv3012'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("pv3012_t"):
            raise TypeError("c_obj type should be <cdata 'struct pv3012'>.")

        self = cls.__new__(cls)
        self._pol = c_obj
        return self

    def _assert_ret(self, ret):
        errmsg = libminerhal.ffi.string(libminerhal.lib.pv3012_errmsg(byref(self._pol))).decode()
        if ret in PV3012._ERROR_CODE_TO_EXCEPTIONS:
            raise PV3012._ERROR_CODE_TO_EXCEPTIONS[ret](errmsg)
        elif ret != 0:
            raise Exception("Unknown return code! \n\tret {0} - errmsg {1}".format(ret, errmsg))

    def init(self):
        """Initialize.

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.pv3012_init(byref(self._pol))
        self._assert_ret(ret)

    def enable(self):
        """Enable output.

        Raises:
            PV3012IOError: if an input/output error occurs
            PV3012ExternalError: if turning on into non-zero output voltage

        """
        ret = libminerhal.lib.pv3012_enable(byref(self._pol))
        self._assert_ret(ret)

    def disable(self):
        """Disable output.

        Raises:
            PV3012IOError: if an input/output error occurs.

        """
        ret = libminerhal.lib.pv3012_disable(byref(self._pol))
        self._assert_ret(ret)

    def is_enabled(self):
        """Check if output is enabled.

        Returns:
            bool: True if enabled, False if disabled

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        is_on = libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.pv3012_is_enabled(byref(self._pol), is_on)
        self._assert_ret(ret)
        return bool(is_on[0])

    def set_voltage_out(self, voltage):
        """Set output voltage.

        Args:
            voltage (float): Output voltage (Volts)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        if not isinstance(voltage, float):
            raise TypeError("voltage type should be float.")

        ret = libminerhal.lib.pv3012_set_voltage_out(byref(self._pol), voltage)
        self._assert_ret(ret)

    def get_voltage_out(self):
        """Get output voltage.

        Returns:
            float: Output voltage (Volts)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        voltage = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_get_voltage_out(byref(self._pol), voltage)
        self._assert_ret(ret)
        return voltage[0]

    def read_voltage_in(self):
        """Read input voltage.

        Returns:
            float: Input voltage (Volts)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        voltage = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_read_voltage_in(byref(self._pol), voltage)
        self._assert_ret(ret)
        return voltage[0]

    def read_voltage_out(self):
        """Read output voltage.

        Returns:
            float: Output voltage (Volts)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        voltage = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_read_voltage_out(byref(self._pol), voltage)
        self._assert_ret(ret)
        return voltage[0]

    def read_current(self):
        """Read output current.

        Returns:
            float: Output current (Amperes)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        current = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_read_current(byref(self._pol), current)
        self._assert_ret(ret)
        return current[0]

    def read_internal_temperature(self):
        """Read internal temperature.

        This returns internal temperature for the PV3012, otherwise knows as temp1.

        Returns:
            float: Temperature (Celsius)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        temperature = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_read_internal_temperature(byref(self._pol), temperature)
        self._assert_ret(ret)
        return temperature[0]

    def read_external_temperature(self):
        """Read external temperature.

        This returns external temperature for the PV3012, otherwise knows as temp2.

        Returns:
            float: Temperature (Celsius)

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        temperature = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pv3012_read_external_temperature(byref(self._pol), temperature)
        self._assert_ret(ret)
        return temperature[0]

    def status(self):
        """Read status.

        Returns:
            dict: Dictionary with "on": <bool>, "power_good": <bool>, "has_faults": <bool> status

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        on, power_good, has_faults = libminerhal.ffi.new("bool *"), libminerhal.ffi.new("bool *"), libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.pv3012_status(byref(self._pol), on, power_good, has_faults)
        self._assert_ret(ret)
        return {'on': bool(on[0]), 'power_good': bool(power_good[0]), 'has_faults': bool(has_faults[0])}

    def clear_faults(self):
        """Clear faults.

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.pv3012_clear_faults(byref(self._pol))
        self._assert_ret(ret)

    def pmbus_get_status(self):
        """Read PMBus status.

        Returns:
            dict: Dictionary with "on": <bool>, "has_faults": <bool>, "faults": <dict of PMBus faults>

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        status = libminerhal.ffi.new("pmbus_status_t *")
        ret = libminerhal.lib.pv3012_pmbus_get_status(byref(self._pol), status)
        self._assert_ret(ret)
        return {'on': bool(status.on), 'has_faults': bool(status.has_faults),
                'faults': {
                    'noneoftheabove': bool(status.faults.noneoftheabove_fault),
                    'cml': bool(status.faults.cml_fault),
                    'temperature': bool(status.faults.temperature_fault),
                    'vin_uv': bool(status.faults.vin_uv_fault),
                    'iout_oc': bool(status.faults.iout_oc_fault),
                    'vout_ov': bool(status.faults.vout_ov_fault),
                    'busy': bool(status.faults.busy_fault),
                    'unknown': bool(status.faults.unknown_fault),
                    'other': bool(status.faults.other_fault),
                    'fans': bool(status.faults.fans_fault),
                    'mfr_specific': bool(status.faults.mfr_specific_fault),
                    'input': bool(status.faults.input_fault),
                    'iout_pout': bool(status.faults.iout_pout_fault),
                    'vout': bool(status.faults.vout_fault),
        }}

    def _check_configuration(self):
        """Check if NVRAM configuration is correct.

        Returns:
            bool: True if configuration is correct, False if configuration is incorrect

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        match = libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.pv3012_check_configuration(byref(self._pol), match)
        self._assert_ret(ret)
        return bool(match[0])

    def _store_configuration(self):
        """Store configuration to NVRAM.

        Raises:
            PV3012IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.pv3012_store_configuration(byref(self._pol))
        self._assert_ret(ret)
