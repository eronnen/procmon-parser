from numpy import datetime64, timedelta64


def filetime_to_datetime64(ft):
    """Convert filetime unsigned 64 bit value to a numpy.datetime64 type.
    """
    if 0 == ft:
        return None
    secs = int(ft // int(1e7))
    nanosecs = int(ft - int(secs * int(1e7))) * 100
    # I use numpy's datetime64 instead of datetime.datetime because filetime have 100 nanoseconds precision.
    return datetime64('1601-01-01') + timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')


def duration_from_100nanosecs(n):
    """Convert 100 nano seconds unsigned 64 bit value to a numpy.timedelta64 type.
    """
    secs = n // (10 ** 7)
    nanosecs = (n - secs * (10 ** 7)) * 100
    return timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')
