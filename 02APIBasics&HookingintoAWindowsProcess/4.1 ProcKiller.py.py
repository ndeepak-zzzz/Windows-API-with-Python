# Import the required module to handle Windows API Calls
import ctypes

# Grab a handle to kernel32.dll & USer32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")


# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)


# Grab The Windows Name from User32
lpWindowName = ctypes.c_char_p(input("Enter Window Name To Kill: ").encode('utf-8'))

# Grab a Handle to the Process
hWnd = u_handle.FindWindowA(None, lpWindowName)

# Check to see if we have the Handle
if hWnd == 0:
	print("[ERROR] Could Not Grab Handle! Error Code: {0}".format(k_handle.GetLastError()))
	exit(1)
else:
	print("[INFO] Grabbed Handle...")
	
# Get the PID of the process at the handle
lpdwProcessId = ctypes.c_ulong()

# We use byref to pass a pointer to the value as needed by the API Call
response = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

# Check to see if the call Completed
if response == 0:
	print("[ERROR] Could Not Get PID from Handle! Error Code: {0}".format(k_handle.GetLastError()))
else:
	print("[INFO] Found PID...")
	

# Opening the Process by PID with Specific Access
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = lpdwProcessId

# Calling the Windows API Call to Open the Process
hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

# Check to see if we have a valid Handle to the process
if hProcess <= 0:
	print("[ERROR] Could Not Grab Privileged Handle! Error Code: {0}".format(k_handle.GetLastError()))
else:
	print("[INFO] Privileged Handle Opened...")
	
# Send Kill to the process
uExitCode = 0x1

response = k_handle.TerminateProcess(hProcess, uExitCode)

if response == 0:
	print("[ERROR] Could Not Kill Process! Error Code: {0}".format(k_handle.GetLastError()))
else:
	print("[INFO] Process Killed...")
	