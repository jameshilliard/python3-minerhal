"""
PAC1710 current sense adc
"""

import minerhal.libminerhal as libminerhal
byref = libminerhal.ffi.addressof

# Errors


class PAC1710Error(IOError):
    """Base exception class for PAC1710 errors."""
    pass


class PAC1710IOError(PAC1710Error):
    """Input/output error."""
    pass


class PAC1710DetectError(PAC1710Error):
    """Detection error."""
    pass


class PAC1710ConfigError(PAC1710Error):
    """Config error."""
    pass


class PAC1710TimeoutError(PAC1710Error):
    """Timeout error."""
    pass

# PAC1710 Object


class PAC1710(object):
    """PAC1710 clock generator driver."""

    _ERROR_CODE_TO_EXCEPTIONS = {
        libminerhal.lib.PAC1710_ERROR_IO: PAC1710IOError,
        libminerhal.lib.PAC1710_ERROR_DETECT: PAC1710DetectError,
        libminerhal.lib.PAC1710_ERROR_CONFIG: PAC1710ConfigError,
        libminerhal.lib.PAC1710_ERROR_TIMEOUT: PAC1710TimeoutError,
    }

    def __init__(self):
        raise NotImplementedError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of PAC1710 that wraps a pac1710_t CFFI object.

        Args:
            c_obj (<cdata 'struct pac1710'>): The pac1710_t CFFI object to wrap

        Returns:
            PAC1710: Instance of PAC1710 wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct pac1710'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("pac1710_t"):
            raise TypeError("c_obj type should be <cdata 'struct pac1710'>.")

        self = cls.__new__(cls)
        self._adc = c_obj
        return self

    def _assert_ret(self, ret):
        errmsg = libminerhal.ffi.string(libminerhal.lib.pac1710_errmsg(byref(self._adc))).decode()
        if ret in PAC1710._ERROR_CODE_TO_EXCEPTIONS:
            raise PAC1710._ERROR_CODE_TO_EXCEPTIONS[ret](errmsg)
        elif ret != 0:
            raise Exception("Unknown return code! \n\tret {0} - errmsg {1}".format(ret, errmsg))

    def init(self):
        """Initialize.

        Raises:
            PAC1710IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.pac1710_init(byref(self._adc))
        self._assert_ret(ret)

    def sense_current(self):
        """Sense current.

        Returns:
            float: Value of the current going through the sense resistor

        Raises:
            PAC1710IOError: if an i2c input/output error occurs
            PAC1710TimeoutError: if a conversion timeout error occurs

        """
        current = libminerhal.ffi.new("float *")
        ret = libminerhal.lib.pac1710_sense_current(byref(self._adc), current)
        self._assert_ret(ret)
        return current[0]
