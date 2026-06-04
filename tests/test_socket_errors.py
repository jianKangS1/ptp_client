import errno

from ptp_client.ptp.client import is_unavailable_local_address_error


class FakeWindowsAddressError(OSError):
    @property
    def winerror(self) -> int:
        return 10049


def test_unavailable_local_address_error_matches_linux_errno() -> None:
    exc = OSError(errno.EADDRNOTAVAIL, "cannot assign requested address")

    assert is_unavailable_local_address_error(exc)


def test_unavailable_local_address_error_matches_windows_winerror() -> None:
    assert is_unavailable_local_address_error(FakeWindowsAddressError())


def test_unavailable_local_address_error_rejects_other_os_errors() -> None:
    exc = OSError(errno.ECONNREFUSED, "connection refused")

    assert not is_unavailable_local_address_error(exc)
