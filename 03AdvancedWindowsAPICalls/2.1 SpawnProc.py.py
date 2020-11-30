# Import the required module to handle Windows API Calls
import ctypes

# Import Python -> Windows Types from ctypes
from ctypes.wintypes import DWORD,LPWSTR,WORD,LPBYTE,HANDLE

# Grab a handle to kernel32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")


# Structure for Startup Info
class STARTUPINFO(ctypes.Structure):
	_fields_ = [
	("cb", DWORD),
	("lpReserved", LPWSTR),
	("lpDesktop", LPWSTR),
	("lpTitle", LPWSTR),
	("dwX", DWORD),
	("dxY", DWORD),
	("dwXSize", DWORD),
	("dwYSize", DWORD),
	("dwXCountChars", DWORD),
	("dwYCountChars", DWORD),
	("dwFillAttribute", DWORD),
	("dwFlags", DWORD),
	("wShowWindow", WORD),
	("cbReserved2", WORD),
	("lpReserved2", LPBYTE),
	("hStdInput", HANDLE),
	("hStdOutput", HANDLE),
	("hStdError", HANDLE),
	]
	
# Structure for Process Info
class PROCESS_INFORMATION(ctypes.Structure):
	_fields_ = [
	("hProcess", HANDLE),
	("hThread", HANDLE),
	("dwProcessId", DWORD),
	("dwThreadId", DWORD),
	]
	
# BOOL CreateProcessW(
# LPWSTR lpApplicationName,
# LPWSTR lpCommandLine,
# LPSECURITY_ATTRIBUTES lpProcessAttributes,
# LPSECURITY_ATTRIBUTES lpThreadAttributes,
# BOOL bInheritHandle,
# DWORD dwCreatedFlags,
# LPVOID lpEnvironment,
# LPCWSTR lpCurrentDirectory,
# LPSTARTUPINFO lpStartupInfo,
# LPPROCESS_INFORMATION, lpProcessInformation
# );

# Setup the Paramaters for the Win API Calls
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
lpEnvironment = None
lpCurrentDirectory = None

# Setup Creation Flags
# CREATE_NEW_CONSOLE Option
dwCreatedFlags = 0x00000010

# Setup to Inherit Handle
# We set this to false as we dont want to inherit the handle into our current process
bInheritHandle = False

# Create StartupInfo Structure
lpStartupInfo = STARTUPINFO()

# Set the Window to Show
lpStartupInfo.wShowWindow = 0x1

# Setup the flags 
# 0x1 = STARTF_USESHOWWINDOW - Tells Windows to check the wShowWindow Flag in the Startup Info
lpStartupInfo.dwFlags = 0x1

# Grab the size of the structure after settings are set
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

# Create empty copy of PROCESS_INFORMATION so the data can be saved to items
lpProcessInformation = PROCESS_INFORMATION()

# Run the API Call
response = k_handle.CreateProcessW(
	lpApplicationName,
	lpCommandLine,
	lpProcessAttributes,
	lpThreadAttributes,
	bInheritHandle,
	dwCreatedFlags,
	lpEnvironment,
	lpCurrentDirectory,
	ctypes.byref(lpStartupInfo),
	ctypes.byref(lpProcessInformation))
	
# Check for Errors
if response > 0:
	print("[INFO] Process Created & Running...")
else:
	print("[ERROR] Could not Create Process! Error Code: {0}".format(k_handle.GetLastError()))



