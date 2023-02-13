"""
This genrates operations that are not common, so we can test them in the resulting PML

run as administrator
"""

import win32api
import win32con
import win32security
import tempfile


def acquire_privilege(privileges):
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_ADJUST_PRIVILEGES |
        win32security.TOKEN_QUERY)

    privileges_enable = []
    for privilege in privileges:
        priv_luid = win32security.LookupPrivilegeValue(None, privilege)
        privileges_enable.append((priv_luid, win32security.SE_PRIVILEGE_ENABLED))
    win32security.AdjustTokenPrivileges(token, False, privileges_enable)


def registry_uncommon():
    """
    calls RegSaveKey, RegLoadKey and RegRestoreKey api, that is intercepted only in Procmon v3.61+
    """
    reg_file = tempfile.mktemp()
    h_save = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Ntfs")
    win32api.RegSaveKeyEx(h_save, reg_file, None, 2)

    h_load = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, "SOFTWARE")
    win32api.RegLoadKey(h_load, "procmon_test", reg_file)


def main():
    acquire_privilege(["SeBackupPrivilege", "SeRestorePrivilege"])
    registry_uncommon()


if __name__ == "__main__":
    main()