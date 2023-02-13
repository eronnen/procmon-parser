from procmon_parser import *

# config = {"FilterRules": [Rule('Process_Name', 'is', 'Procmon.exe', 'exclude'), Rule('Process_Name', 'is', 'Procmon64.exe', 'exclude'), Rule('Process_Name', 'is', 'Explorer.exe', 'exclude'), Rule('Event_Class', 'is', 'File System', 'include'), Rule('PID', 'is', '15876', 'include'), Rule('TID', 'contains', '1234', 'exclude'),
#                           Rule('Architecture', 'is', '32-bit', 'include')]}
#
# with open(r"C:\Temp\TestPIDConfig1.pmc", "wb") as f:
#     dump_configuration(config, f)

f = open(r"C:\Users\elyro\Downloads\delete_test_v3.70\delete_test.pml", "rb")
r = ProcmonLogsReader(f)
for i, log in enumerate(r):
    print(f"{i} - {log.__repr__()}")
