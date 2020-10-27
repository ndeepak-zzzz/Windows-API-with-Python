# Import the required module to handle Windows API Calls
import ctypes

# Grab a handle to kernel32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")

# Win API Call
# HANDLE OpenProcess(
# DWORD dwDesiredAccess,
# BOOL bInheritHandle,
# DWAORD dwProcessId
# );

# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Setting Up The Params
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = 0x100c # Replace This With Your Own!


# Calling the Windows API Call
response = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

# Check For Errors
error = k_handle.GetLastError()
if error != 0:
	print("Handle Not Created!")
	print("Error Code: {0}".format(error))
	exit(1)

# Check to see if we have a valid Handle
if response <= 0:
	print("Handle Not Created!")
elif response >= 1:
	print("Handle Created!")


