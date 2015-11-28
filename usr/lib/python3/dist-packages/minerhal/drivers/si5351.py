"""
SI5351 clock generator driver and errors.
"""

import minerhal.libminerhal as libminerhal
byref = libminerhal.ffi.addressof

# Errors


class SI5351Error(IOError):
    """Base exception class for SI5351 errors."""
    pass


class SI5351IOError(SI5351Error):
    """Input/output error."""
    pass

# SI5351 Object


class SI5351(object):
    """SI5351 clock generator driver."""

    _ERROR_CODE_TO_EXCEPTIONS = {
        libminerhal.lib.SI5351_ERROR_IO: SI5351IOError,
    }

    def __init__(self):
        raise NotImplementedError("This class can only be constructed from the C structure object.")

    @classmethod
    def from_c_obj(cls, c_obj):
        """Create an instance of SI5351 that wraps a si5351_t CFFI object.

        Args:
            c_obj (<cdata 'struct si5351'>): The si5351_t CFFI object to wrap

        Returns:
            SI5351: Instance of SI5351 wrapping the CFFI object

        Raises:
            TypeError: if `c_obj` type is not <cdata 'struct si5351'>

        """
        if libminerhal.ffi.typeof(c_obj) is not libminerhal.ffi.typeof("si5351_t"):
            raise TypeError("c_obj type should be <cdata 'struct si5351'>.")

        self = cls.__new__(cls)
        self._clkgen = c_obj
        return self

    def _assert_ret(self, ret):
        errmsg = libminerhal.ffi.string(libminerhal.lib.si5351_errmsg(byref(self._clkgen))).decode()
        if ret in SI5351._ERROR_CODE_TO_EXCEPTIONS:
            raise SI5351._ERROR_CODE_TO_EXCEPTIONS[ret](errmsg)
        elif ret != 0:
            raise Exception("Unknown return code! \n\tret {0} - errmsg {1}".format(ret, errmsg))

    def init(self):
        """Initialize. Clock outputs will be enabled after initialization.

        Raises:
            SI5351IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.si5351_init(byref(self._clkgen))
        self._assert_ret(ret)

    def lock_detect(self):
        """Lock detect.

        Returns:
            bool: True if PLLs locked, False if PLLs are not locked

        Raises:
            SI5351IOError: if an input/output error occurs

        """
        locked = libminerhal.ffi.new("bool *")
        ret = libminerhal.lib.si5351_lock_detect(byref(self._clkgen), locked)
        self._assert_ret(ret)
        return bool(locked)

    def disable_outputs(self):
        """Disable clock outputs.

        Raises:
            SI5351IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.si5351_disable_outputs(byref(self._clkgen))
        self._assert_ret(ret)

    def enable_outputs(self):
        """Enable clock outputs.

        Raises:
            SI5351IOError: if an input/output error occurs

        """
        ret = libminerhal.lib.si5351_enable_outputs(byref(self._clkgen))
        self._assert_ret(ret)

