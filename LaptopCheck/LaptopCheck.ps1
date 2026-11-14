<#
    LaptopCheck.ps1  -  Used laptop / PC pre-purchase inspector for Windows 10 / 11

    Start it with "Run-LaptopCheck.bat" (it asks for administrator rights by itself).
    The tool only LOOKS. It does not uninstall, delete or change settings and it uploads nothing.
    (The only things it writes are its own report folder, plus Windows' own logs from the
     battery report, the disk speed test and the optional Defender scan.)

    Options (for advanced use):
      -DefenderScan Ask|Quick|Full|None   malware scan choice (default: ask)
      -StressSeconds 45                   length of the CPU load test
      -SkipStress -SkipDiskBench -SkipFileScan -NoPrompt -NoOpen -NoElevate
      -OutRoot <folder>                   where to save reports (default: .\Reports next to this script)
#>
[CmdletBinding()]
param(
    [ValidateSet('Buy','Own','Sell')][string]$Mode = 'Buy',
    [ValidateSet('Ask','Quick','Full','None')][string]$DefenderScan = 'Ask',
    [int]$StressSeconds = 45,
    [switch]$SkipStress,
    [switch]$SkipDiskBench,
    [switch]$SkipFileScan,
    [switch]$NoPrompt,
    [switch]$NoElevate,
    [switch]$NoOpen,
    [string]$OutRoot
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:ToolVersion    = '1.0.0'
$script:Start          = Get-Date
$script:Own            = ($Mode -eq 'Own')
$script:Sell           = ($Mode -eq 'Sell')
if ($script:Own -and -not $PSBoundParameters.ContainsKey('StressSeconds')) { $StressSeconds = 180 }
if ($script:Sell -and -not $PSBoundParameters.ContainsKey('StressSeconds')) { $StressSeconds = 90 }
# values collected for the eBay listing (sell mode) and the parts check
$script:Spec = [ordered]@{}; $script:SpecDrives = @(); $script:GpuNames = @(); $script:BatList = @(); $script:DriveModels = @()
try { $Host.UI.RawUI.WindowTitle = $(if ($script:Own) { 'My Laptop Health Check' } elseif ($script:Sell) { 'Laptop Check - Selling' } else { 'Laptop Check' }) } catch {}

#region ===================== elevation =====================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$script:IsAdmin = Test-IsAdmin
if (-not $script:IsAdmin -and -not $NoElevate) {
    Write-Host 'Asking for administrator rights (needed for the full set of checks)...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" } }
        else { $a += "-$($kv.Key)"; $a += ('"{0}"' -f $kv.Value) }
    }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($a -join ' ') -ErrorAction Stop; exit 0 }
    catch { Write-Host 'Administrator rights were not given. Continuing in LIMITED mode - several checks will be skipped.' -ForegroundColor Yellow }
}
#endregion

#region ===================== helpers =====================
$script:Metrics  = [ordered]@{}
$script:Results  = New-Object System.Collections.ArrayList
$script:Appendix = [ordered]@{}
$script:SigCache = @{}

function Add-R {
    param([string]$Cat, [string]$Check, [ValidateSet('PASS','WARN','FAIL','INFO','MANUAL')][string]$Status, [string]$Detail = '', [string]$Advice = '')
    [void]$script:Results.Add([pscustomobject]@{ Category = $Cat; Check = $Check; Status = $Status; Detail = $Detail; Advice = $Advice })
    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } 'MANUAL' { 'Cyan' } default { 'Gray' } }
    Write-Host ('   [{0,-6}] {1}' -f $Status, $Check) -ForegroundColor $color
}
function Add-Appendix([string]$Title, $Rows) { $r = @($Rows | Where-Object { $_ }); if ($r.Count -gt 0) { $script:Appendix[$Title] = $r } }
function Invoke-Section([string]$Name, [scriptblock]$Body) {
    Write-Host ''
    Write-Host ("== $Name ==") -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Body } catch { Add-R $Name 'Section error' 'INFO' ('This section hit an error and may be incomplete: ' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')') }
    Write-Host ('   ({0:N0}s)' -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}
function HE([object]$s) { if ($null -eq $s) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Save-Raw([string]$Name, $Content) { try { $Content | Out-File -FilePath (Join-Path $script:RawDir $Name) -Encoding utf8 -Width 4096 } catch {} }
function Get-Reg([string]$Path, [string]$Name) { try { $v = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $null } }
function Get-RegProps([string]$Path) { try { Get-ItemProperty -LiteralPath $Path -ErrorAction Stop } catch { $null } }
function Get-Cim([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter) {
    try {
        if ($Filter) { Get-CimInstance -Namespace $Namespace -ClassName $Class -Filter $Filter -ErrorAction Stop }
        else { Get-CimInstance -Namespace $Namespace -ClassName $Class -ErrorAction Stop }
    } catch { $null }
}
function Get-Events([hashtable]$Filter, [int]$Max = 300) { try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { @() } }
function Short([string]$s, [int]$n = 300) { if (-not $s) { return '' }; $s = ($s -replace '\s+', ' ').Trim(); if ($s.Length -gt $n) { return $s.Substring(0, $n) + '...' }; $s }
function Join-Lines($items, [int]$max = 25) {
    $a = @($items | Where-Object { $_ })
    $out = ($a | Select-Object -First $max) -join "`n"
    if ($a.Count -gt $max) { $out += "`n... and $($a.Count - $max) more (see appendix)" }
    $out
}
function Norm([string]$s) { ($s -replace '[^A-Za-z0-9]', '').ToLower() }
function Test-Advertised([string]$Adv, [string[]]$Actual) {
    $n = Norm $Adv
    if (-not $n) { return $null }
    $stop = @('intel','amd','core','nvidia','geforce','radeon','with','graphics','gb','the','processor','cpu','gpu','laptop','gen','th','ryzen','apple')
    $tokens = @(($Adv.ToLower() -split '[^a-z0-9]+') | Where-Object { $_.Length -ge 2 -and $stop -notcontains $_ })
    foreach ($a in $Actual) {
        $na = Norm $a
        if (-not $na) { continue }
        if ($na.Contains($n)) { return $true }
        if ($tokens.Count -gt 0) {
            $all = $true
            foreach ($t in $tokens) { if (-not $na.Contains($t)) { $all = $false; break } }
            if ($all) { return $true }
        }
    }
    return $false
}
function Get-ExePath([string]$Cmd) {
    if (-not $Cmd) { return $null }
    try {
        $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
        if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $c = $c.Substring(1, $e - 1) } }
        elseif ($c -match '^(.+?\.(exe|com|bat|cmd|dll|sys|scr|ps1|vbs|js|cpl|ocx))(\s|$|,|")') { $c = $Matches[1] }
        if ($c -match '^\\\?\?\\') { $c = $c.Substring(4) }
        if ($c -match '^(?i)\\SystemRoot\\') { $c = $env:SystemRoot + $c.Substring(11) }
        if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
        if (-not [IO.Path]::IsPathRooted($c)) {
            foreach ($d in @("$env:SystemRoot\System32", $env:SystemRoot)) { $t = Join-Path $d $c; if (Test-Path -LiteralPath $t -PathType Leaf) { $c = $t; break } }
        }
        return $c
    } catch { return $null }
}
function Get-Sig([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Path = $Path; Exists = $false; Status = 'NoPath'; Signer = ''; IsMicrosoft = $false } }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = [pscustomobject]@{ Path = $Path; Exists = $false; Status = 'Missing'; Signer = ''; IsMicrosoft = $false }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $r.Exists = $true
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r.Status = [string]$s.Status
            if ($s.SignerCertificate) {
                $subj = $s.SignerCertificate.Subject
                $r.Signer = ($subj -replace '^CN=(?:"([^"]+)"|([^,]+)).*$', '$1$2')
                $r.IsMicrosoft = ($subj -match 'O=Microsoft Corporation')
            }
        }
    } catch { $r.Status = 'Error' }
    $script:SigCache[$Path] = $r
    $r
}
function Test-Internet {
    try { $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 6; return ($r.Content -match 'Microsoft Connect Test') } catch { return $false }
}
function Format-GB([double]$bytes) { '{0:N0} GB' -f ($bytes / 1e9) }

# --- native helpers (fast file walker, CPU load, RAM pattern test, firmware type) ---
$script:HasNative = $false
$csharp = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

public static class LcNative {
    [DllImport("kernel32.dll")] public static extern bool GetFirmwareType(ref uint FirmwareType);
}
public class LcHit { public string FilePath; public string Reason; public long Size; public DateTime Modified; public bool Hidden; }
public static class LcWalker {
    public static long Total; public static long Dirs; public static long Denied;
    public static List<LcHit> Scan(string root, string execExts, string badNameRx, string riskyDirRx, int max) {
        var exts = new HashSet<string>(execExts.Split(','), StringComparer.OrdinalIgnoreCase);
        var bad = new Regex(badNameRx, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var risky = new Regex(riskyDirRx, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var dbl = new Regex(@"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|mp3|mp4|avi|mkv|mov|zip|rar|7z|html?)\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|cpl|jar|msi)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var res = new List<LcHit>();
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0) {
            string dir = stack.Pop();
            Dirs++;
            string[] subs = null, files = null;
            try { files = Directory.GetFiles(dir); } catch { Denied++; }
            try { subs = Directory.GetDirectories(dir); } catch { }
            if (files != null) {
                string dirSlash = dir.EndsWith("\\") ? dir : dir + "\\";
                bool riskyDir = risky.IsMatch(dirSlash);
                bool recentDir = dirSlash.IndexOf("\\Recent\\", StringComparison.OrdinalIgnoreCase) >= 0;
                bool inUsers = dirSlash.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase) >= 0;
                foreach (var f in files) {
                    Total++;
                    string name; string ext;
                    try { name = Path.GetFileName(f); ext = Path.GetExtension(f); } catch { continue; }
                    if (ext.Length > 1) ext = ext.Substring(1);
                    bool isExec = exts.Contains(ext);
                    string reason = null;
                    if (name.IndexOf('\u202E') >= 0) reason = "Hidden right-to-left trick in file name";
                    else if (!recentDir && dbl.IsMatch(name)) reason = "Fake double extension (e.g. .pdf.exe)";
                    else if (isExec && bad.IsMatch(name)) reason = "Name matches known malware / hacking / piracy tool";
                    bool hidden = false;
                    if (reason == null && isExec && (riskyDir || inUsers)) {
                        try {
                            var a = File.GetAttributes(f);
                            hidden = (a & FileAttributes.Hidden) != 0;
                            if (riskyDir) reason = "Program/script in an unusual location";
                            else if (hidden) reason = "Hidden program/script in a user folder";
                        } catch { }
                    }
                    if (reason != null && res.Count < max) {
                        var h = new LcHit(); h.FilePath = f; h.Reason = reason; h.Hidden = hidden;
                        try { var fi = new FileInfo(f); h.Size = fi.Length; h.Modified = fi.LastWriteTime; } catch { }
                        res.Add(h);
                    }
                }
            }
            if (subs != null) {
                foreach (var s in subs) {
                    try { var a = File.GetAttributes(s); if ((a & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                    stack.Push(s);
                }
            }
        }
        return res;
    }
}
public static class LcStress {
    static volatile bool run;
    static List<Thread> threads = new List<Thread>();
    public static void Start(int n) {
        run = true; threads.Clear();
        for (int i = 0; i < n; i++) { var t = new Thread(Work); t.IsBackground = true; t.Priority = ThreadPriority.BelowNormal; t.Start(); threads.Add(t); }
    }
    static void Work() { double x = 1.0001; while (run) { for (int i = 0; i < 200000; i++) { x = Math.Sqrt(x * x + 1.0) * 1.0000001; if (x > 1e12) x = 1.0001; } } }
    public static void Stop() { run = false; foreach (var t in threads) t.Join(3000); }
    public static int TestedMB;
    public static long MemTest(int megabytes) {
        long errors = 0; TestedMB = 0;
        const int chunk = 8388608; // 64 MB of longs
        var blocks = new List<long[]>();
        try { for (int i = 0; i < megabytes / 64; i++) { blocks.Add(new long[chunk]); TestedMB += 64; } } catch (OutOfMemoryException) { }
        ulong[] pats = { 0x5555555555555555UL, 0xAAAAAAAAAAAAAAAAUL, 0UL, 0xFFFFFFFFFFFFFFFFUL };
        foreach (var p in pats) {
            long lp = unchecked((long)p);
            foreach (var b in blocks) for (int i = 0; i < b.Length; i++) b[i] = lp;
            foreach (var b in blocks) for (int i = 0; i < b.Length; i++) if (b[i] != lp) errors++;
        }
        for (int k = 0; k < blocks.Count; k++) { var b = blocks[k]; long seed = ((long)k << 32) ^ 0x1234567L; for (int i = 0; i < b.Length; i++) b[i] = seed ^ i; }
        for (int k = 0; k < blocks.Count; k++) { var b = blocks[k]; long seed = ((long)k << 32) ^ 0x1234567L; for (int i = 0; i < b.Length; i++) if (b[i] != (seed ^ i)) errors++; }
        blocks.Clear(); GC.Collect();
        return errors;
    }
}
'@
try { Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction Stop; $script:HasNative = $true } catch { Write-Host "Note: could not load fast helpers ($($_.Exception.Message)). Some tests will be skipped." -ForegroundColor Yellow }

# WinRT await helper (Bluetooth / radio state)
function Invoke-WinRtAwait($Op, [Type]$ResultType, [int]$TimeoutMs = 15000) {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $m = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    $task = $m.MakeGenericMethod($ResultType).Invoke($null, @($Op))
    if ($task.Wait($TimeoutMs)) { return $task.Result }
    return $null
}
#endregion

#region ===================== knowledge base =====================
$script:BrandInfo = @{
    'Dell'      = @{ Bios = 'F2 (tap repeatedly at the Dell logo)'; Boot = 'F12'; Diag = 'Press F12 at the Dell logo and choose "Diagnostics" (or hold Fn while pressing Power) to run Dell ePSA / SupportAssist pre-boot diagnostics. In Windows: SupportAssist > Hardware scan.'; Warranty = 'https://www.dell.com/support/home/en-us/product-support/servicetag/{SERIAL}/overview'; Lock = 'In the BIOS check: Security > Admin/System password = not set; Security > Absolute = Disabled or "Permanently disabled"; no Asset Tag or ownership text with a company name.'; Notes = 'XPS / Precision / Latitude: check for a swollen battery (touchpad raised or lid not closing flat).' }
    'Lenovo'    = @{ Bios = 'ThinkPad: press Enter at the logo, then F1. IdeaPad / Yoga / Legion: F2, or the small "Novo" pin-hole button'; Boot = 'F12'; Diag = 'ThinkPad: press Enter at the logo, then F10 for Lenovo Diagnostics. Others: Lenovo Vantage > Device > Hardware scan.'; Warranty = 'https://pcsupport.lenovo.com/ (enter the serial number)'; Lock = 'ThinkPad SUPERVISOR password is the big risk - it is very hard to remove (often needs a board/chip replacement). Check Security > Password and Security > Absolute Persistence Module.'; Notes = 'ThinkPads are very common ex-company machines - be strict about the company-lock checks.' }
    'HP'        = @{ Bios = 'Press Esc at power-on, then F10'; Boot = 'Esc then F9'; Diag = 'Press Esc at power-on then F2 for "HP PC Hardware Diagnostics UEFI" and run the Extensive test (or at least System Fast Test + Memory test).'; Warranty = 'https://support.hp.com/check-warranty'; Lock = 'In the BIOS check: Security > Administrator / Setup password not set; "Absolute Persistence Module" = Inactive/Disabled; no "Ownership Tag" or "Asset Tracking Number" with a company name; Sure Admin / Enhanced BIOS Authentication off.'; Notes = 'EliteBook / ProBook / ZBook are business lines - often ex-corporate.' }
    'ASUS'      = @{ Bios = 'Hold F2 while pressing Power'; Boot = 'Esc'; Diag = 'MyASUS app > Customer Support > System Diagnosis (run all).'; Warranty = 'https://www.asus.com/support/warranty-status-inquiry/'; Lock = 'BIOS > Security: Administrator / User password not set.'; Notes = 'ROG / TUF gaming models: watch GPU and CPU temperatures under load and listen to the fans.' }
    'Acer'      = @{ Bios = 'F2 at the logo'; Boot = 'F12 (may need enabling in BIOS)'; Diag = 'Acer Care Center > Checkup.'; Warranty = 'https://www.acer.com/ (Support > Warranty, enter the serial / SNID)'; Lock = 'BIOS > Security: Supervisor / User / HDD password not set.'; Notes = '' }
    'MSI'       = @{ Bios = 'Delete (or F2) at the logo'; Boot = 'F11'; Diag = 'MSI Center > Support > diagnostics / system info.'; Warranty = 'https://www.msi.com/support (Warranty check)'; Lock = 'BIOS > Security: Administrator / User password not set.'; Notes = 'Gaming laptops: check GPU temperatures and fans under load.' }
    'Microsoft' = @{ Bios = 'Shut down, hold Volume-Up, press and release Power, keep holding Volume-Up until the Surface logo goes away'; Boot = 'Volume-Down + Power (USB boot)'; Diag = 'Install the "Surface Diagnostic Toolkit" / Surface app from the Microsoft Store and run all tests.'; Warranty = 'https://support.microsoft.com/devices (warranty shows after registering the serial)'; Lock = 'In Surface UEFI look for a "Surface Enterprise Management Mode (SEMM)" / management certificate page - if present the device is company-locked.'; Notes = 'Surface Pro / Laptop: check the screen is not lifting (swollen battery) and the screen has no touch "ghosting".' }
    'Razer'     = @{ Bios = 'F1 or F2 / Delete at the logo'; Boot = 'F12'; Diag = 'Razer Synapse / Razer support tools.'; Warranty = 'https://mysupport.razer.com'; Lock = 'BIOS password not set.'; Notes = 'Razer Blades are known for swelling batteries - check the touchpad and the base sit flat.' }
    'Samsung'   = @{ Bios = 'F2 at the logo'; Boot = 'F10'; Diag = 'Samsung Settings / Samsung Update apps.'; Warranty = 'https://www.samsung.com/support'; Lock = 'BIOS password not set.'; Notes = '' }
    'Huawei'    = @{ Bios = 'F2 at the logo'; Boot = 'F12'; Diag = 'PC Manager > Scan / Hardware check.'; Warranty = 'https://consumer.huawei.com/support/warranty-query/'; Lock = 'BIOS password not set.'; Notes = '' }
    'Honor'     = @{ Bios = 'F2 at the logo'; Boot = 'F12'; Diag = 'PC Manager > Hardware check.'; Warranty = 'https://www.honor.com/global/support/'; Lock = 'BIOS password not set.'; Notes = '' }
    'Framework' = @{ Bios = 'F2 at the logo'; Boot = 'F12'; Diag = 'Built-in: hold the side power button / see Framework knowledge base for diagnostic LEDs.'; Warranty = 'https://frame.work/support'; Lock = 'BIOS password not set.'; Notes = 'Check every expansion card slot with a USB device.' }
    'Gigabyte'  = @{ Bios = 'F2 or Delete'; Boot = 'F12'; Diag = 'Gigabyte / Aorus Control Center.'; Warranty = 'https://www.gigabyte.com/Support'; Lock = 'BIOS password not set.'; Notes = '' }
    'Toshiba'   = @{ Bios = 'F2 at the logo'; Boot = 'F12'; Diag = 'Dynabook / Toshiba PC Diagnostic Tool.'; Warranty = 'https://support.dynabook.com/'; Lock = 'BIOS supervisor password not set.'; Notes = '' }
    'Fujitsu'   = @{ Bios = 'F2 at the logo'; Boot = 'F12'; Diag = 'Fujitsu DeskUpdate / diagnostic tools.'; Warranty = 'https://support.ts.fujitsu.com/'; Lock = 'BIOS passwords not set.'; Notes = 'Lifebooks are business machines - often ex-corporate.' }
    'Apple'     = @{ Bios = 'Not applicable (Boot Camp)'; Boot = 'Hold Option at start-up'; Diag = 'Hold D at start-up for Apple Diagnostics.'; Warranty = 'https://checkcoverage.apple.com'; Lock = 'IMPORTANT: also boot into macOS and check that Activation Lock / Find My is OFF and there is no firmware password - Windows cannot check this.'; Notes = '' }
}
$script:DefaultBrand = @{ Bios = 'Try F2, Delete, F10, F1 or Esc at the logo. Any brand: Settings > System > Recovery > Advanced start-up > Restart now > Troubleshoot > Advanced options > UEFI Firmware Settings'; Boot = 'F12, F11, F9 or Esc'; Diag = 'Use the manufacturer''s own diagnostics app if there is one.'; Warranty = ''; Lock = 'BIOS / UEFI: no administrator, supervisor or power-on password; no anti-theft (Absolute / Computrace) enabled.'; Notes = '' }

$script:BusinessRx = 'Latitude|Precision|OptiPlex|Vostro|ThinkPad|ThinkCentre|ThinkStation|ThinkBook|EliteBook|ProBook|ZBook|Dragonfly|EliteDesk|ProDesk|ExpertBook|ExpertCenter|TravelMate|Lifebook|Celsius|Toughbook|Getac|Surface.*Business|Pro Book'

# Product signatures: category, severity, product, regex
$script:SigDB = @(
    # --- company device management (strong sign it still belongs to an organisation)
    @('Company management','FAIL','Microsoft Configuration Manager (SCCM) client','CcmExec|SMS Agent Host|Configuration Manager Client'),
    @('Company management','FAIL','Microsoft Intune management agent','IntuneManagementExtension|Intune Management Extension'),
    @('Company management','FAIL','VMware Workspace ONE / AirWatch','AirWatch|Workspace ONE|VMware Hub|AWACMClient'),
    @('Company management','FAIL','Ivanti / MobileIron / LANDesk','MobileIron|LANDesk|\bIvanti'),
    @('Company management','FAIL','ManageEngine Endpoint Central','ManageEngine|Desktop Central|UEMS_Agent|ManageEngine UEMS'),
    @('Company management','FAIL','Kaseya VSA','Kaseya'),
    @('Company management','FAIL','ConnectWise Automate (LabTech)','LTService|LTSvcMon|LabTech|ConnectWise Automate'),
    @('Company management','FAIL','Datto RMM','CagService|AEMAgent|Datto RMM|CentraStage'),
    @('Company management','FAIL','NinjaOne RMM','NinjaRMM|NinjaOne'),
    @('Company management','FAIL','N-able / SolarWinds RMM','N-able|N-central|SolarWinds MSP|Advanced Monitoring Agent'),
    @('Company management','FAIL','Tanium','Tanium'),
    @('Company management','FAIL','HCL BigFix','BigFix|BESClient'),
    @('Company management','FAIL','JumpCloud','JumpCloud'),
    @('Company management','FAIL','Atera RMM','\bAtera'),
    @('Company management','FAIL','Action1 RMM','Action1'),
    @('Company management','FAIL','Syxsense','Syxsense'),
    @('Company management','FAIL','Pulseway','Pulseway'),
    @('Company management','FAIL','Tactical RMM','TacticalRMM|tacticalagent|Tactical RMM'),
    @('Company management','FAIL','Syncro RMM','SyncroLive|Syncro Device|Kabuto'),
    @('Company management','FAIL','Level RMM','level-agent|Level\.io'),
    @('Company management','FAIL','SuperOps RMM','SuperOps'),
    @('Company management','FAIL','Absolute / Computrace anti-theft','Absolute Persistence|Computrace|rpcnet|\bCTES|Absolute Software|LoJack'),
    # --- company security agents (means it was a company PC and was not wiped)
    @('Company security agent','WARN','CrowdStrike Falcon','CrowdStrike|CSFalcon'),
    @('Company security agent','WARN','SentinelOne','SentinelOne|SentinelAgent'),
    @('Company security agent','WARN','VMware Carbon Black','Carbon Black|CbDefense|CarbonBlack'),
    @('Company security agent','WARN','Cylance','Cylance'),
    @('Company security agent','WARN','Palo Alto Cortex XDR','Cortex XDR|cyserver\.exe'),
    @('Company security agent','WARN','Tenable / Nessus agent','Nessus Agent|Tenable'),
    @('Company security agent','WARN','Qualys agent','Qualys'),
    @('Company security agent','WARN','Rapid7 Insight agent','Rapid7|ir_agent'),
    @('Company security agent','WARN','Zscaler','Zscaler'),
    @('Company security agent','WARN','Netskope','Netskope'),
    @('Company security agent','WARN','Palo Alto GlobalProtect VPN','GlobalProtect|PanGPS'),
    @('Company security agent','WARN','Cisco Secure Client / AnyConnect / Umbrella','AnyConnect|Cisco Secure Client|vpnagent|Umbrella Roaming'),
    @('Company security agent','WARN','Forcepoint','Forcepoint|Websense'),
    @('Company security agent','WARN','Symantec Endpoint Protection','Symantec Endpoint|SepMasterService'),
    @('Company security agent','WARN','McAfee / Trellix agent','McAfee Agent|Trellix|\bmasvc|macmnsvc'),
    @('Company security agent','WARN','Trend Micro Apex One / Deep Security','Apex One|OfficeScan|Deep Security Agent'),
    @('Company security agent','WARN','ESET Management Agent','ESET Management Agent|ERAAgent'),
    @('Company security agent','WARN','Kaspersky Security Center agent','klnagent|Kaspersky Security Center'),
    @('Company security agent','WARN','Bitdefender GravityZone','GravityZone|EPSecurityService|Endpoint Security Tools'),
    @('Company security agent','WARN','Sophos Endpoint (business)','Sophos Endpoint|Sophos MCS'),
    @('Company security agent','WARN','Citrix','Citrix'),
    @('Company security agent','WARN','Okta Verify / Duo','Okta Verify|Duo Authentication|Duo Device Health'),
    @('Company security agent','WARN','FortiClient','FortiClient|FortiTray'),
    # --- remote control tools (someone else could control the PC)
    @('Remote access','WARN','TeamViewer','TeamViewer'),
    @('Remote access','WARN','AnyDesk','AnyDesk'),
    @('Remote access','WARN','RustDesk','RustDesk'),
    @('Remote access','WARN','ScreenConnect / ConnectWise Control','ScreenConnect|ConnectWise Control'),
    @('Remote access','WARN','Splashtop','Splashtop'),
    @('Remote access','WARN','LogMeIn / GoTo','LogMeIn|GoTo Resolve|GoToAssist|GoTo Opener'),
    @('Remote access','WARN','VNC server','RealVNC|TightVNC|UltraVNC|TigerVNC|winvnc|vncserver'),
    @('Remote access','WARN','Radmin','Radmin'),
    @('Remote access','WARN','Ammyy Admin','Ammyy'),
    @('Remote access','WARN','Supremo','Supremo'),
    @('Remote access','WARN','AeroAdmin','AeroAdmin'),
    @('Remote access','WARN','NetSupport Manager (often abused as a RAT)','NetSupport|client32\.exe'),
    @('Remote access','WARN','Zoho Assist','Zoho Assist|ZohoMeeting|ZA_Connect'),
    @('Remote access','WARN','DWService','DWService|DWAgent'),
    @('Remote access','WARN','Remote Utilities','Remote Utilities|rutserv|rfusclient'),
    @('Remote access','WARN','MeshCentral agent','MeshAgent|MeshCentral'),
    @('Remote access','WARN','Chrome Remote Desktop host','Chrome Remote Desktop|remoting_host'),
    @('Remote access','WARN','HopToDesk','HopToDesk'),
    @('Remote access','WARN','UltraViewer','UltraViewer'),
    @('Remote access','WARN','ToDesk / Sunlogin','\bToDesk|Sunlogin|\bOray|AweSun'),
    @('Remote access','WARN','DameWare / BeyondTrust / Bomgar','DameWare|BeyondTrust|Bomgar'),
    @('Remote access','WARN','SimpleHelp / FixMe.IT / RemotePC / Getscreen','SimpleHelp|FixMe\.IT|RemotePC|Getscreen|Iperius Remote|ShowMyPC'),
    @('Remote access','INFO','Parsec (game streaming)','\bParsec'),
    # --- spyware / keyloggers (deal-breaker)
    @('Spyware / keylogger','FAIL','Spy / keylogger software','Refog|Spyrix|KidLogger|Revealer Keylogger|Logixoft|Ardamax|SpyAgent|Spytech|WebWatcher|FlexiSPY|\bmSpy\b|Hoverwatch|Elite Keylogger|Actual Keylogger|Perfect Keylogger|Blazingtools|All In One Keylogger|PC Pandora|Win-Spy|Realtime-Spy|NetVizor|SentryPC|Wolfeye|iSpyoo|\bkeylogger'),
    @('Employee monitoring','WARN','Employee monitoring software','Teramind|ActivTrak|Hubstaff|Veriato|Spector ?360|SpectorSoft|InterGuard|Controlio|StaffCop|Time Doctor|Kickidler|Work Examiner|Clever Control|Insightful\.io|Workpuls|DeskTime|EmpMonitor|CurrentWare|BrowseControl|Imperceptus'),
    @('Parental control','WARN','Parental control software','Qustodio|Net Nanny|Norton Family|Kaspersky Safe Kids|Mobicip|FamiSafe|Covenant Eyes'),
    # --- hacking tools / RATs / password stealers (deal-breaker)
    @('Malware / hacking tool','FAIL','Remote-access trojan or hacking tool','njRAT|DarkComet|QuasarRAT|AsyncRAT|Remcos|NanoCore|Orcus RAT|DCRat|XWorm|NetWire|Warzone RAT|mimikatz|LaZagne|meterpreter'),
    # --- crypto miners (deal-breaker: wears the hardware, often malware)
    @('Crypto miner','FAIL','Cryptocurrency miner','xmrig|xmr-stak|NiceHash|PhoenixMiner|NBMiner|lolMiner|\bGMiner|TeamRedMiner|cpuminer|\bminerd\b|ethminer|Claymore|nanominer|SRBMiner|Kryptex|Cudo Miner|Honeyminer|MinerGate|WildRig|t-rex\.exe'),
    # --- pirated Windows / Office activators (deal-breaker: no real licence, often bundled malware)
    @('Piracy / activator','FAIL','Windows/Office crack or activator','KMSpico|KMSAuto|AutoKMS|KMS_VL_ALL|KMSELDI|Microsoft Toolkit|SECOH-QAD|Windows Loader|Re-Loader|KMSTools|HEU KMS|KMS Matrix|vlmcsd|\bAAct\.exe|\bOInstall'),
    @('Piracy / activator','WARN','Cracked software / game repacks','FitGirl|DODI[- ]Repack|(?<!ssh-)\bkeygen\b|\bcrack(ed)?\.exe'),
    # --- adware / junk that should not be on a clean sale machine
    @('Adware / junk','WARN','Adware / potentially unwanted program','WebCompanion|Lavasoft|DriverPack|Reimage|Restoro|Fortect|Segurazo|SAntivirus|ByteFence|Wave ?Browser|OneLaunch|Shift Browser|PC Accelerate|MyPC Utilities|Advanced SystemCare|Systweak|Advanced System Optimizer|Search Protect|Conduit|MyWay|Mindspark|Hola VPN|\bBonzi|PC App Store|Auslogics BoostSpeed|Driver Easy|Driver Booster|360 Total Security|Qihoo|Tencent PC Manager|Baidu')
)

$script:BadFileNameRx = 'xmrig|xmr-stak|nicehash|phoenixminer|nbminer|lolminer|gminer|teamredminer|cpuminer|minerd|ethminer|nanominer|srbminer|t-rex\.exe|kmspico|kmsauto|autokms|kms_vl_all|kmseldi|secoh-qad|mimikatz|lazagne|njrat|darkcomet|asyncrat|remcos|nanocore|quasarrat|dcrat|xworm|netwire|keylogger|(?<!ssh-)keygen|ardamax|spyrix|refog|kidlogger|crack(ed)?\.exe|activator\.exe|hacktool|meterpreter|payload\.exe'
$script:RiskyDirRx = '(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\AppData\\Roaming\\$|\\AppData\\Local\\$|\\AppData\\LocalLow\\$|^[A-Za-z]:\\ProgramData\\$|^[A-Za-z]:\\$|\\Start Menu\\Programs\\Startup\\|\\Windows\\Tasks\\|\\Windows\\Fonts\\|\\Windows\\Debug\\|\\Windows\\Help\\|\\Windows\\addins\\|\\System32\\Tasks\\|\\Music\\|\\Pictures\\|\\Videos\\|\\Windows\\(INF|Cursors|Media)\\|\\PerfLogs\\)'
$script:ExecExts = 'exe,dll,scr,com,pif,cpl,sys,msi,bat,cmd,ps1,psm1,vbs,vbe,js,jse,wsf,wsh,hta,jar'
$script:CmdBadRx = '(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,}|\s-e\s+[A-Za-z0-9+/=]{40,}|FromBase64String|DownloadString|DownloadFile|DownloadData|Net\.WebClient|\bIEX\b|Invoke-Expression|mshta(\.exe)?\s+["]?(https?|javascript|vbscript)|regsvr32.+/i:https?|scrobj\.dll|certutil.+-urlcache|bitsadmin.+/transfer|rundll32.+javascript:)'
$script:CmdOddRx = '(?i)(-w(indowstyle)?\s+h(idden)?\b|wscript|cscript|mshta|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Windows\\Temp\\)'
#endregion

#region ===================== identity + output folder =====================
$cs   = Get-Cim Win32_ComputerSystem | Select-Object -First 1
$csp  = Get-Cim Win32_ComputerSystemProduct | Select-Object -First 1
$bios = Get-Cim Win32_BIOS | Select-Object -First 1
$bb   = Get-Cim Win32_BaseBoard | Select-Object -First 1
$os   = Get-Cim Win32_OperatingSystem | Select-Object -First 1
$encl = Get-Cim Win32_SystemEnclosure | Select-Object -First 1

$script:Manufacturer = ('' + $cs.Manufacturer).Trim()
$script:Model        = ('' + $cs.Model).Trim()
$script:FriendlyModel = $script:Model
if ($script:Manufacturer -match 'LENOVO' -and $csp.Version -and $csp.Version -ne $script:Model) { $script:FriendlyModel = "$($csp.Version) (type $($script:Model))" }
$script:Serial  = ('' + $bios.SerialNumber).Trim()
$script:Brand   = 'Other'
switch -Regex ("$($script:Manufacturer) $($script:Model)") {
    'VMware|VirtualBox|innotek|QEMU|KVM|Xen|Parallels|Bochs|Virtual Machine' { $script:Brand = 'Virtual'; break }
    'Alienware|^\s*Dell' { $script:Brand = 'Dell'; break }
    'LENOVO' { $script:Brand = 'Lenovo'; break }
    '^\s*(HP|Hewlett)' { $script:Brand = 'HP'; break }
    'ASUS' { $script:Brand = 'ASUS'; break }
    '^\s*Acer' { $script:Brand = 'Acer'; break }
    'Micro-Star|^\s*MSI' { $script:Brand = 'MSI'; break }
    'Microsoft' { $script:Brand = 'Microsoft'; break }
    'Razer' { $script:Brand = 'Razer'; break }
    'Samsung' { $script:Brand = 'Samsung'; break }
    'HUAWEI' { $script:Brand = 'Huawei'; break }
    'HONOR' { $script:Brand = 'Honor'; break }
    'Framework' { $script:Brand = 'Framework'; break }
    'GIGABYTE|AORUS' { $script:Brand = 'Gigabyte'; break }
    'TOSHIBA|Dynabook' { $script:Brand = 'Toshiba'; break }
    'FUJITSU' { $script:Brand = 'Fujitsu'; break }
    'Apple' { $script:Brand = 'Apple'; break }
}
$chassis = @($encl.ChassisTypes)
$script:IsLaptop = ($cs.PCSystemType -eq 2) -or (@($chassis | Where-Object { @(8,9,10,11,12,14,18,21,30,31,32) -contains $_ }).Count -gt 0)

$here = Split-Path -Parent $PSCommandPath
if (-not $OutRoot) { $OutRoot = Join-Path $here 'Reports' }
$safe = (("$($script:Manufacturer)_$($script:Model)_$($script:Serial)") -replace '[^A-Za-z0-9_.-]', '-') -replace '-{2,}', '-'
if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$script:OutDir = Join-Path $OutRoot ("$($stamp)_" + $(if ($script:Own) { 'MINE_' } elseif ($script:Sell) { 'SELL_' } else { 'BUY_' }) + $safe)
try { New-Item -ItemType Directory -Path $script:OutDir -Force -ErrorAction Stop | Out-Null; [IO.File]::WriteAllText((Join-Path $script:OutDir '.write-test'), 'x'); Remove-Item (Join-Path $script:OutDir '.write-test') -Force }
catch {
    $script:OutDir = Join-Path $env:TEMP "LaptopCheck\$($stamp)_$safe"
    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    Write-Host "The USB folder is not writable - saving the report to $($script:OutDir) instead." -ForegroundColor Yellow
}
$script:RawDir = Join-Path $script:OutDir 'raw'
New-Item -ItemType Directory -Path $script:RawDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $script:RawDir 'console-log.txt') -Force | Out-Null } catch {}
#endregion

#region ===================== intro + questions =====================
Clear-Host
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host $(if ($script:Own) { "  MY LAPTOP HEALTH CHECK (after buying)   v$($script:ToolVersion)" } elseif ($script:Sell) { "  LAPTOP CHECK - SELLING (makes your eBay listing)   v$($script:ToolVersion)" } else { "  LAPTOP / PC PRE-PURCHASE CHECK   v$($script:ToolVersion)" }) -ForegroundColor Cyan
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host ("  Detected : {0} {1}" -f $script:Manufacturer, $script:FriendlyModel)
Write-Host ("  Serial   : {0}" -f $script:Serial)
Write-Host ("  Windows  : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("  Mode     : {0}" -f $(if ($script:IsAdmin) { 'Administrator (full checks)' } else { 'LIMITED - not administrator' }))
Write-Host '  This tool only reads information. It does not change or delete anything.' -ForegroundColor DarkGray
Write-Host ''

$script:Adv = @{ Model = ''; Cpu = ''; Ram = ''; Storage = ''; Gpu = '' }
if (-not $NoPrompt -and -not $script:Sell) {
    Write-Host $(if ($script:Own) { 'Optional: type what the listing/receipt PROMISED so the tool can check you got it.' } else { 'Optional: type what the seller ADVERTISED so the tool can compare it to the real hardware.' }) -ForegroundColor Cyan
    Write-Host 'Just press Enter to skip any question.' -ForegroundColor DarkGray
    $script:Adv.Model   = Read-Host '  Advertised brand + model (e.g. Dell XPS 15 9510)'
    $script:Adv.Cpu     = Read-Host '  Advertised processor     (e.g. i7-1165G7 or Ryzen 7 5800H)'
    $script:Adv.Ram     = Read-Host '  Advertised RAM in GB     (e.g. 16)'
    $script:Adv.Storage = Read-Host '  Advertised storage in GB (e.g. 512, or 1 for 1 TB)'
    $script:Adv.Gpu     = Read-Host '  Advertised graphics card (e.g. RTX 3060) - blank if none'
}
if ($DefenderScan -eq 'Ask') {
    if ($NoPrompt) { $DefenderScan = $(if ($script:Own) { 'Full' } else { 'Quick' }) }
    else {
        Write-Host ''
        Write-Host 'Microsoft Defender malware scan (runs at the end):' -ForegroundColor Cyan
        Write-Host ('  Q = Quick scan (about 5-15 min - the places malware normally hides)' + $(if (-not $script:Own) { '   [default]' }))
        Write-Host ('  F = Full scan  (reads EVERY file on the disk - 30 min to 2+ hours)' + $(if ($script:Own) { '   [default - recommended for a laptop you just bought]' }))
        Write-Host '  N = No Defender scan'
        $c = Read-Host '  Choose Q / F / N'
        if ($c -match '^\s*[fF]') { $DefenderScan = 'Full' } elseif ($c -match '^\s*[qQ]') { $DefenderScan = 'Quick' } elseif ($c -match '^\s*[nN]') { $DefenderScan = 'None' } else { $DefenderScan = $(if ($script:Own) { 'Full' } else { 'Quick' }) }
    }
}
$script:WantMemDiag = $false; $script:WantRuntime = $false
if (($script:Own -or $script:Sell) -and -not $NoPrompt) {
    Write-Host ''
    Write-Host $(if ($script:Sell) { 'Extra tests (their results go into your listing):' } else { 'Extra tests for your own laptop:' }) -ForegroundColor Cyan
    $script:WantRuntime = ((Read-Host '  Measure real battery run-time? (runs 2 min on battery) [Y/n]') -notmatch '^\s*[nN]')
    if ($script:IsAdmin -and $script:Own) { $script:WantMemDiag = ((Read-Host '  Schedule the full Windows Memory Diagnostic for the next restart (~20 min)? [y/N]') -match '^\s*[yY]') }
    $sl = Read-Host "  CPU stress test length in seconds [$StressSeconds]"
    if ($sl -match '^\s*(\d+)\s*$') { $StressSeconds = [int]$Matches[1] }
}
Write-Host ''
Write-Host 'Tip: keep the charger connected (you will be asked to unplug it once, briefly).' -ForegroundColor DarkGray
$script:Online = Test-Internet
#endregion

#region ===================== shared inventory =====================
Write-Host ''
Write-Host 'Collecting inventory (programs, services, tasks, users)...' -ForegroundColor DarkGray

# user registry hives (load hives of users who are not logged in, read-only use, unloaded at the end)
$script:MountedHives = @()
$script:Profiles = @(Get-Cim Win32_UserProfile | Where-Object { -not $_.Special -and $_.SID -match '^S-1-(5-21|12-1)-' })
if ($script:IsAdmin) {
    foreach ($pr in $script:Profiles) {
        if (Test-Path ("Registry::HKEY_USERS\" + $pr.SID)) { continue }
        $dat = Join-Path $pr.LocalPath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $hn = 'LC_' + $pr.SID
        $null = & reg.exe load "HKU\$hn" "$dat" 2>&1
        if ($LASTEXITCODE -eq 0) { $script:MountedHives += $hn }
    }
}
$script:UserHives = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^(S-1-(5-21|12-1)-[\d-]+|LC_.+)$' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { $_.PSChildName })
function Get-HiveUser([string]$h) {
    $sid = $h -replace '^LC_', ''
    $p = $script:Profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
    if ($p) { return (Split-Path $p.LocalPath -Leaf) }
    return $sid
}

# installed programs
$progs = New-Object System.Collections.ArrayList
$uPaths = @(@{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; S = 'All users' }, @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; S = 'All users' })
foreach ($h in $script:UserHives) { $uPaths += @{ P = "Registry::HKEY_USERS\$h\Software\Microsoft\Windows\CurrentVersion\Uninstall"; S = (Get-HiveUser $h) } }
foreach ($up in $uPaths) {
    foreach ($k in @(Get-ChildItem -LiteralPath $up.P -ErrorAction SilentlyContinue)) {
        $p = Get-RegProps $k.PSPath
        if (-not $p -or -not $p.DisplayName) { continue }
        [void]$progs.Add([pscustomobject]@{ Name = $p.DisplayName; Publisher = $p.Publisher; Version = $p.DisplayVersion; InstallDate = $p.InstallDate; Location = $p.InstallLocation; For = $up.S; Hidden = [bool]($p.SystemComponent -eq 1) })
    }
}
$script:Programs = @($progs | Sort-Object Name, For -Unique)
$script:Services = @(Get-Cim Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, Description)
$script:Processes = @(Get-Cim Win32_Process | Select-Object Name, ProcessId, ExecutablePath, CommandLine)
$script:Tasks = @()
try {
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        foreach ($a in @($t.Actions)) {
            $script:Tasks += [pscustomobject]@{ Path = "$($t.TaskPath)$($t.TaskName)"; State = [string]$t.State; Author = $t.Author; Execute = $a.Execute; Arguments = $a.Arguments }
        }
    }
} catch {}
$script:Pnp = @()
try { $script:Pnp = @(Get-PnpDevice -PresentOnly -ErrorAction Stop) } catch {}

# top-level folder names in common install locations
$folderNames = New-Object System.Collections.ArrayList
$fRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
foreach ($pr in $script:Profiles) { $fRoots += (Join-Path $pr.LocalPath 'AppData\Roaming'); $fRoots += (Join-Path $pr.LocalPath 'AppData\Local'); $fRoots += (Join-Path $pr.LocalPath 'AppData\Local\Programs') }
foreach ($r in $fRoots) { if ($r -and (Test-Path -LiteralPath $r)) { foreach ($d in @(Get-ChildItem -LiteralPath $r -Directory -Force -ErrorAction SilentlyContinue)) { [void]$folderNames.Add([pscustomobject]@{ Root = $r; Name = $d.Name; Full = $d.FullName; Created = $d.CreationTime }) } } }
$script:Folders = @($folderNames)

# haystack for product signature matching
$hay = New-Object System.Collections.ArrayList
foreach ($p in $script:Programs)  { [void]$hay.Add(@('Installed program', "$($p.Name) | $($p.Publisher) | $($p.Location)", "$($p.Name) ($($p.Publisher))")) }
foreach ($s in $script:Services)  { [void]$hay.Add(@('Service', "$($s.Name) | $($s.DisplayName) | $($s.PathName)", "$($s.DisplayName) [$($s.Name)] - $($s.State)")) }
foreach ($p in $script:Processes) { [void]$hay.Add(@('Running process', "$($p.Name) | $($p.ExecutablePath)", "$($p.Name) ($($p.ExecutablePath))")) }
foreach ($t in $script:Tasks)     { [void]$hay.Add(@('Scheduled task', "$($t.Path) | $($t.Execute) | $($t.Arguments)", "$($t.Path) -> $($t.Execute)")) }
foreach ($f in $script:Folders)   { [void]$hay.Add(@('Folder', $f.Name, $f.Full)) }
$script:SigHits = New-Object System.Collections.ArrayList
foreach ($sig in $script:SigDB) {
    $rx = $sig[3]
    foreach ($h in $hay) {
        if ($h[1] -match $rx) { [void]$script:SigHits.Add([pscustomobject]@{ Category = $sig[0]; Severity = $sig[1]; Product = $sig[2]; Source = $h[0]; Evidence = $h[2] }) }
    }
}
function Report-SigCategory([string]$ResultCat, [string[]]$SigCats, [string]$Advice) {
    $hits = @($script:SigHits | Where-Object { $SigCats -contains $_.Category })
    foreach ($g in @($hits | Group-Object Product)) {
        $first = $g.Group[0]
        $ev = Join-Lines (@($g.Group | ForEach-Object { "$($_.Source): $($_.Evidence)" } | Select-Object -Unique)) 6
        Add-R $ResultCat $g.Name $first.Severity $ev $Advice
    }
    return $hits.Count
}
#endregion

#region ===================== CHECKS =====================

Invoke-Section 'System identity' {
    $cat = 'Identity'
    $det = "Manufacturer: $($script:Manufacturer)`nModel: $($script:FriendlyModel)`nSystem SKU: $($cs.SystemSKUNumber)`nSerial / service tag: $($script:Serial)`nMotherboard: $($bb.Manufacturer) $($bb.Product) (serial $($bb.SerialNumber))`nBIOS: $($bios.SMBIOSBIOSVersion) dated $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') })`nWindows: $($os.Caption) $($os.Version) (build $($os.BuildNumber)), installed $(if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') })`nComputer name: $($env:COMPUTERNAME)`nUp since: $($os.LastBootUpTime)"
    Add-R $cat 'Machine identity' INFO $det 'Check that the serial number above matches the sticker on the bottom of the laptop and the box/receipt. A mismatch can mean a swapped motherboard or a stolen unit.'
    if ($script:Brand -eq 'Virtual') { Add-R $cat 'Real hardware' FAIL "This is a VIRTUAL MACHINE ($($script:Manufacturer) $($script:Model)), not the real laptop." 'You are not testing real hardware. Run the tool directly on the laptop.' }
    if ($script:Serial -match '^(|0+|To be filled.*|Default string|System Serial Number|None|Not Applicable|N/A|OEM|123456789|Chassis Serial Number|\s+)$') {
        Add-R $cat 'Serial number' WARN "Serial number is blank or generic: '$($script:Serial)'." 'Normal only for some home-built desktops. On a brand laptop it usually means the motherboard was replaced/repaired, so warranty and stolen-status cannot be checked.'
    } else { Add-R $cat 'Serial number' PASS "Serial number is present: $($script:Serial)" }
    if ($script:Adv.Model) {
        $actual = @("$($script:Manufacturer) $($script:Model) $($csp.Version) $($csp.Name) $($cs.SystemFamily)")
        $toks = @(($script:Adv.Model.ToLower() -split '[^a-z0-9]+') | Where-Object { $_.Length -ge 2 })
        $found = @($toks | Where-Object { (Norm $actual[0]).Contains($_) })
        if ($toks.Count -gt 0 -and $found.Count -ge [math]::Ceiling($toks.Count / 2)) { Add-R $cat 'Model matches advert' PASS "Advertised: $($script:Adv.Model)`nDetected: $($actual[0])" }
        else { Add-R $cat 'Model matches advert' WARN "Advertised: $($script:Adv.Model)`nDetected: $($actual[0])" 'The firmware reports a different model than advertised. Compare carefully (some brands use internal codes) - ask the seller to explain.' }
    }
    if ("$($script:FriendlyModel) $($cs.SystemFamily)" -match $script:BusinessRx) {
        Add-R $cat 'Business-class model' INFO "$($script:FriendlyModel) is a business line machine." 'These are very often ex-company laptops. Pay extra attention to the Company lock section, the BIOS password and Absolute/Computrace. Ask for proof of purchase or a release letter from the company.'
    }
    $bi = $script:BrandInfo[$script:Brand]; if (-not $bi) { $bi = $script:DefaultBrand }
    $w = ''; if ($bi.Warranty) { $w = $bi.Warranty -replace '\{SERIAL\}', [uri]::EscapeDataString($script:Serial) }
    Add-R $cat 'Warranty / ownership lookup' MANUAL ("Look up the serial on the maker's site: " + $(if ($w) { $w } else { "search '$($script:Manufacturer) warranty check'" })) 'Check the warranty status, the original country, and whether it is listed as a business/enterprise unit. Do it on your phone before paying.'
}

Invoke-Section 'Company lock & ownership' {
    $cat = 'Company lock'
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { Add-R $cat 'PowerShell lockdown' FAIL "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode." 'This is set by companies (AppLocker / WDAC). Strong sign the PC is still company-managed.' }

    # Entra ID (Azure AD) / domain join
    $raw = (& dsregcmd.exe /status 2>&1 | Out-String)
    Save-Raw 'dsregcmd.txt' $raw
    $ds = @{}
    foreach ($line in ($raw -split "`r?`n")) { if ($line -match '^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$') { if (-not $ds.ContainsKey($Matches[1])) { $ds[$Matches[1]] = $Matches[2] } } }
    $joined = $false
    if ($ds['AzureAdJoined'] -eq 'YES') { $joined = $true; Add-R $cat 'Joined to a company (Entra ID / Azure AD)' FAIL "AzureAdJoined = YES`nOrganisation: $($ds['TenantName']) $($ds['TenantId'])`nMDM: $($ds['MdmUrl'])" 'The laptop is registered to an organisation. Even after a reset it may demand a company login. Only buy if the company removes it from their Entra/Intune/Autopilot - get that in writing.' }
    if ($ds['DomainJoined'] -eq 'YES' -or $cs.PartOfDomain) { $joined = $true; Add-R $cat 'Joined to a company domain' FAIL "Domain: $($cs.Domain) $($ds['DomainName'])" 'This PC belongs to a company network domain. It must be removed from the domain and fully reset by the seller.' }
    if ($ds['EnterpriseJoined'] -eq 'YES') { $joined = $true; Add-R $cat 'Enterprise joined' FAIL 'EnterpriseJoined = YES' 'Company-registered device.' }
    if (-not $joined) { Add-R $cat 'Company directory join' PASS 'Not joined to Entra ID / Azure AD or a Windows domain.' }
    if ($ds['WorkplaceJoined'] -eq 'YES') { Add-R $cat 'Work/school account added' WARN "A work or school account is connected (WorkplaceJoined = YES). $($ds['TenantName'])" 'Ask the seller to remove it (Settings > Accounts > Access work or school) - or just reset the PC.' }

    # MDM enrolment
    $enr = @()
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue)) {
        $p = Get-RegProps $k.PSPath
        if ($p -and $p.ProviderID -and ($p.UPN -or $p.DiscoveryServiceFullURL)) { $enr += "Provider: $($p.ProviderID)  User: $($p.UPN)  Server: $($p.DiscoveryServiceFullURL)" }
    }
    if ($enr.Count) { Add-R $cat 'MDM enrolment (Intune or similar)' FAIL (Join-Lines $enr) 'The PC is enrolled in a company device-management system that can lock, wipe or track it remotely.' }
    else { Add-R $cat 'MDM enrolment' PASS 'No mobile-device-management enrolment found.' }

    # Autopilot
    $ap = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'
    $apTenant = $ap.CloudAssignedTenantDomain
    if (-not $apTenant) {
        $cache = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache' 'PolicyJsonCache'
        if ($cache -and $cache -match '"CloudAssignedTenantDomain"\s*:\s*"([^"]+)"') { $apTenant = $Matches[1] }
    }
    if ($apTenant) { Add-R $cat 'Windows Autopilot registration' FAIL "Registered in Autopilot to: $apTenant" 'After ANY reset this laptop will show a company sign-in screen and cannot be used until that company releases it. Do not buy unless the company deregisters it.' }
    else { Add-R $cat 'Windows Autopilot registration' PASS 'No Autopilot profile cached on this PC.' }
    Add-R $cat 'Reset test (best proof)' MANUAL 'The only 100% test for Autopilot / company lock: ask the seller to reset the PC (Settings > System > Recovery > Reset this PC > Remove everything) WHILE CONNECTED TO WI-FI, in front of you.' 'At the first setup screens there must be no "Welcome to <company>" page and no demand for a work/school account.'

    # Defender for Endpoint onboarding
    if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState') -eq 1) { Add-R $cat 'Microsoft Defender for Endpoint (company)' FAIL 'The PC is onboarded to a company''s Defender for Endpoint security console.' 'The company can monitor and isolate this PC remotely.' }

    # Absolute / Computrace files (BIOS-level anti-theft that reinstalls itself)
    $abs = @()
    foreach ($f in @("$env:SystemRoot\System32\rpcnet.exe", "$env:SystemRoot\System32\rpcnetp.exe", "$env:SystemRoot\System32\rpcnetp.dll", "$env:SystemRoot\SysWOW64\rpcnet.exe", "$env:SystemRoot\SysWOW64\rpcnetp.exe", "$env:SystemRoot\System32\AbsoluteAgent.exe")) { if (Test-Path -LiteralPath $f) { $abs += $f } }
    foreach ($s in $script:Services) { if ($s.Name -match '^(rpcnet|rpcnetp|CTESPersistence|Absolute)') { $abs += "Service: $($s.Name) ($($s.State))" } }
    if ($abs.Count) { Add-R $cat 'Absolute / Computrace anti-theft' FAIL (Join-Lines $abs) 'This anti-theft agent lives in the BIOS and comes back after reinstalling Windows. The owner (often a company) can track or lock the laptop. Check BIOS: Absolute must be Disabled / Permanently disabled.' }
    else { Add-R $cat 'Absolute / Computrace anti-theft (Windows side)' PASS 'No Absolute/Computrace agent files found in Windows.' 'Still check the BIOS setting (see Brand-specific section).' }

    # management agents (SCCM, RMM, etc.) + security agents
    $n = Report-SigCategory $cat @('Company management') 'A company management agent is installed. The laptop is (or was) controlled by an organisation. It must be released and fully reset.'
    $n2 = Report-SigCategory $cat @('Company security agent') 'Company security/VPN software left behind: this was a company PC and was not wiped. Insist on a full reset and ask for proof it was released.'
    if (($n + $n2) -eq 0) { Add-R $cat 'Company management / security agents' PASS 'No company management, RMM or enterprise security agents found.' }

    # SCCM folder
    if (Test-Path "$env:SystemRoot\CCM") { Add-R $cat 'Configuration Manager folder' FAIL "$env:SystemRoot\CCM exists" 'SCCM client present - company managed.' }

    # group policy / WSUS / login banner / owner fields
    $wsus = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
    if ($wsus) { Add-R $cat 'Company update server (WSUS)' WARN "Windows Update is pointed at: $wsus" 'Set by a company policy. Updates may not work outside that company.' }
    $pol = 0
    try { $pol = [int](@(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.ValueCount }) | Measure-Object -Sum).Sum } catch {}
    $polTop = (@(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ', ')
    if ($pol -gt 80) { Add-R $cat 'Windows group policies' WARN "$pol Windows policy values are set ($polTop)." 'A large number of Windows policies usually means company management (or heavy tweaking). A full reset removes them.' }
    else { Add-R $cat 'Windows group policies' INFO "$pol Windows policy values set ($polTop). Normal for a home PC." }
    $sysPol = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (("$($sysPol.LegalNoticeCaption)$($sysPol.LegalNoticeText)" -replace '[\s\x00]', '')) { Add-R $cat 'Login warning banner' WARN ("Title: $($sysPol.LegalNoticeCaption)`nText: " + (Short $sysPol.LegalNoticeText 400)) 'A legal notice at login is typical for company PCs and often names the company.' }
    $reg = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $org = "$($reg.RegisteredOrganization)".Trim()
    if ($org -and $org -notmatch '^(|Microsoft|HP|Hewlett-Packard.*|Dell.*|Lenovo|ASUS.*|Acer|Toshiba|Samsung|MSI|Organization|Organisation)$') { Add-R $cat 'Registered organisation' WARN "Windows is registered to organisation: '$org' (owner '$($reg.RegisteredOwner)')" 'Indicates the PC was set up by a company.' }
    else { Add-R $cat 'Registered owner' INFO "Owner: '$($reg.RegisteredOwner)'  Organisation: '$org'" }
    $tag = ('' + $encl.SMBIOSAssetTag).Trim()
    if ($tag -and $tag -notmatch '^(|No Asset Tag|No Asset Information|Default string|Asset-1234567890|To be filled.*|0+|None|N/A|\s+|Not Specified)$') { Add-R $cat 'BIOS asset tag' WARN "Asset tag set in firmware: '$tag'" 'Companies tag their laptops. Ask the seller where it came from and for proof it was released/sold legally.' }
    else { Add-R $cat 'BIOS asset tag' PASS 'No company asset tag in the firmware.' }

    # provisioning packages, kiosk mode
    try {
        $pp = @(Get-ProvisioningPackage -AllInstalledPackages -ErrorAction Stop)
        $oem = '(?i)AMD|Intel|NVIDIA|Qualcomm|Realtek|Microsoft|HP|Dell|Lenovo|ASUS|Acer|MSI|Samsung|Surface|OEM|Power|Display|Audio'
        $foreign = @($pp | Where-Object { "$($_.PackageName) $($_.PackagePath)" -notmatch $oem })
        if ($foreign.Count) { Add-R $cat 'Provisioning packages' WARN (Join-Lines ($foreign | ForEach-Object { "$($_.PackageName) $($_.PackagePath)" })) 'Provisioning packages are used by companies to configure PCs.' }
        elseif ($pp.Count) { Add-R $cat 'Provisioning packages' INFO (Join-Lines ($pp | ForEach-Object { "$($_.PackageName)" })) 'These look like normal manufacturer packages.' }
    } catch {}
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration') { Add-R $cat 'Kiosk / assigned access' WARN 'Assigned-access (kiosk) configuration exists.' 'The PC may be locked to one app for some users.' }
    $vpn = @(); try { $vpn += @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue); $vpn += @(Get-VpnConnection -ErrorAction SilentlyContinue) } catch {}
    if ($vpn.Count) { Add-R $cat 'Saved VPN connections' INFO (Join-Lines ($vpn | ForEach-Object { "$($_.Name) -> $($_.ServerAddress)" })) 'Company VPNs here suggest a company PC.' }
}

Invoke-Section 'Windows licence & edition' {
    $cat = 'Windows licence'
    $lic = @(Get-Cim SoftwareLicensingProduct 'root\cimv2' "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL")
    $svc = Get-Cim SoftwareLicensingService | Select-Object -First 1
    $statusTxt = @{ 0 = 'Unlicensed'; 1 = 'Licensed (activated)'; 2 = 'Initial grace'; 3 = 'Additional grace'; 4 = 'Non-genuine grace'; 5 = 'Notification (NOT activated)'; 6 = 'Extended grace' }
    $l = $lic | Where-Object { $_.LicenseStatus -eq 1 } | Select-Object -First 1
    if (-not $l) { $l = $lic | Select-Object -First 1 }
    if ($l) {
        $st = [int]$l.LicenseStatus
        $d = "Product: $($l.Name)`nChannel: $($l.ProductKeyChannel) ($($l.Description))`nStatus: $($statusTxt[$st])`nKey ends: $($l.PartialProductKey)"
        $script:Spec['Windows'] = ("$($os.Caption)" -replace '^Microsoft\s+', '') + $(if ($st -eq 1) { ', genuine and activated' } else { ' (NOT activated)' })
        if ($st -eq 1) { Add-R $cat 'Windows activation' PASS $d } else { Add-R $cat 'Windows activation' FAIL $d 'Windows is not activated. You may need to buy a licence (unless the firmware key below works after a reset).' }
        $kms = "$($svc.KeyManagementServiceMachine)$($l.KeyManagementServiceMachine)$($l.DiscoveredKeyManagementServiceMachineName)"
        if ($l.Description -match 'VOLUME_KMSCLIENT') {
            if ($kms -match '127\.0\.0\.|0\.0\.0\.0|localhost|kms\.|msguides|digiboy|\.ir\b|\.ru\b|lotro|kmspico|loli') { Add-R $cat 'Activation method' FAIL "KMS activation via '$kms'" 'Activated with a pirate KMS server/activator. Not a real licence; activators often come with malware.' }
            else { Add-R $cat 'Activation method' WARN "KMS (company volume) activation. KMS host: '$kms'" 'Company volume licence - it stops working ~180 days after leaving the company network. You will need your own licence (or a reset that uses the firmware key).' }
        } elseif ($l.ProductKeyChannel -match 'MAK|Volume') { Add-R $cat 'Activation method' WARN "Volume licence channel: $($l.ProductKeyChannel)" 'Company volume licence - not transferable to you.' }
        else { Add-R $cat 'Activation method' PASS "Channel: $($l.ProductKeyChannel)" }
    } else { Add-R $cat 'Windows activation' WARN 'Could not read the licence information.' 'Check Settings > System > Activation manually.' }
    $oa3 = "$($svc.OA3xOriginalProductKey)"
    if ($oa3.Length -ge 5) { Add-R $cat 'Licence key built into firmware' PASS ("A Windows key is stored in the laptop's firmware (ends in ...$($oa3.Substring($oa3.Length - 5))).") 'Good: after a clean reinstall, Windows activates automatically with this key.' }
    else { Add-R $cat 'Licence key built into firmware' INFO 'No OEM Windows key in firmware (normal for custom PCs or retail-licensed machines).' 'Make sure Windows is activated with a digital licence before buying.' }
    $ed = "$($os.Caption)"
    if ($ed -match 'Enterprise|Education|LTSC|IoT') { Add-R $cat 'Windows edition' WARN "Edition: $ed" 'Enterprise/Education/LTSC editions are company/school licences (or pirated). Your licence will likely be invalid after you take it home.' }
    else { Add-R $cat 'Windows edition' INFO "Edition: $ed" }
    if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'SkuPolicyRequired') -eq 1) { Add-R $cat 'S mode' WARN 'Windows is in S mode (only Microsoft Store apps can be installed).' 'You can switch out for free (one-way) in the Microsoft Store.' }
    $build = [int]$os.BuildNumber
    if ($build -lt 19045) { Add-R $cat 'Windows version' WARN "Build $build is outdated / unsupported." 'Update Windows or reinstall a current version.' }
    elseif ($build -lt 22000) { Add-R $cat 'Windows version' INFO "Windows 10 (build $build). Windows 10 support ended October 2025." 'Check the Firmware section to see if it can run Windows 11.' }
    else { Add-R $cat 'Windows version' PASS "Windows 11 (build $build)." }
}

Invoke-Section 'Firmware & security chip' {
    $cat = 'Firmware'
    $fw = 0; $fwTxt = 'unknown'
    if ($script:HasNative) { try { $t = [uint32]0; if ([LcNative]::GetFirmwareType([ref]$t)) { $fw = $t } } catch {} }
    if ($fw -eq 2) { $fwTxt = 'UEFI' } elseif ($fw -eq 1) { $fwTxt = 'Legacy BIOS' }
    $sb = $null; try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
    if ($sb -eq $true) { Add-R $cat 'Secure Boot' PASS "Secure Boot is ON ($fwTxt)." }
    elseif ($sb -eq $false) { Add-R $cat 'Secure Boot' WARN "Secure Boot is OFF ($fwTxt)." 'Normally ON. Someone turned it off - could be for Linux, or to load unsigned/cheat/rootkit drivers. Turn it back on in the BIOS.' }
    else { Add-R $cat 'Secure Boot' INFO "Secure Boot state could not be read (firmware: $fwTxt)." }
    if ($fw -eq 1) { Add-R $cat 'Firmware mode' WARN 'Running in Legacy BIOS mode.' 'Windows 11 needs UEFI. Old or reconfigured.' }

    $tpmVer = ''
    $wt = Get-Cim Win32_Tpm 'root\cimv2\security\microsofttpm' | Select-Object -First 1
    if ($wt) { $tpmVer = ("" + $wt.SpecVersion).Split(',')[0].Trim() }
    $tpm = $null; try { $tpm = Get-Tpm -ErrorAction Stop } catch {}
    if ($tpm -and $null -eq $tpm.TpmPresent) { $tpm = $null }
    if ($tpm) {
        $d ="Present: $($tpm.TpmPresent)  Ready: $($tpm.TpmReady)  Enabled: $($tpm.TpmEnabled)  Version: $tpmVer  Maker: $($tpm.ManufacturerIdTxt)"
        if (-not $tpm.TpmPresent) { Add-R $cat 'TPM security chip' WARN $d 'No TPM visible. It may be disabled in the BIOS. Windows 11 requires TPM 2.0.' }
        elseif ($tpmVer -and $tpmVer -notmatch '^2') { Add-R $cat 'TPM security chip' WARN $d 'TPM 1.2 only - not enough for Windows 11.' }
        else { Add-R $cat 'TPM security chip' PASS $d }
    } elseif ($wt) { Add-R $cat 'TPM security chip' PASS "TPM present, version $tpmVer" }
    else { Add-R $cat 'TPM security chip' INFO 'TPM status could not be read (needs admin) or no TPM.' }

    $cpu = Get-Cim Win32_Processor | Select-Object -First 1
    if ($cpu.VirtualizationFirmwareEnabled -eq $false) { Add-R $cat 'Virtualisation (VT-x / AMD-V)' INFO 'Virtualisation is disabled in the BIOS.' 'Only matters for WSL, Android apps, virtual machines.' }
    $dg = Get-Cim Win32_DeviceGuard 'root\Microsoft\Windows\DeviceGuard' | Select-Object -First 1
    if ($dg) { Add-R $cat 'Memory integrity / VBS' INFO ("VBS status: $($dg.VirtualizationBasedSecurityStatus) (2 = running). Services running: " + (@($dg.SecurityServicesRunning) -join ',')) }
    if ($bios.ReleaseDate) {
        $age = ((Get-Date) - $bios.ReleaseDate).TotalDays / 365
        if ($age -gt 4) { Add-R $cat 'BIOS age' INFO ("BIOS version $($bios.SMBIOSBIOSVersion) is about {0:N1} years old." -f $age) 'Update the BIOS from the maker''s website after buying (fixes bugs, battery and security issues).' }
    }
    $so = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SystemStartOptions'
    if ($so -match 'TESTSIGNING|DISABLE_INTEGRITY_CHECKS|NOINTEGRITYCHECKS') { Add-R $cat 'Driver signature enforcement' FAIL "Boot options: $so" 'Windows is set to load unsigned kernel drivers (test signing / integrity checks off). Used by rootkits and game cheats. Major red flag on a sale machine.' }
    elseif ($so -match 'DEBUG') { Add-R $cat 'Kernel debug mode' WARN "Boot options: $so" 'Kernel debugging is enabled - unusual.' }
    else { Add-R $cat 'Driver signature enforcement' PASS 'Normal boot - only signed drivers allowed.' }
}

Invoke-Section 'Brand-specific checks' {
    $cat = 'Company lock'
    $bcat = 'Brand-specific'
    $bi = $script:BrandInfo[$script:Brand]; if (-not $bi) { $bi = $script:DefaultBrand }
    Add-R $bcat "How to open BIOS ($($script:Brand))" MANUAL "BIOS/UEFI setup: $($bi.Bios)`nBoot menu: $($bi.Boot)" "In the BIOS: $($bi.Lock)"
    Add-R $bcat "Maker's own hardware diagnostics" MANUAL $bi.Diag 'Run the long/extensive test if the seller has time. It tests RAM, disk, battery, fans, screen and more at hardware level.'
    if ($bi.Notes) { Add-R $bcat 'Model notes' INFO $bi.Notes }

    switch ($script:Brand) {
        'Lenovo' {
            $pw = Get-Cim Lenovo_BiosPasswordSettings 'root\wmi' | Select-Object -First 1
            if ($pw) {
                $s = [int]$pw.PasswordState
                $set = @(); if ($s -band 1) { $set += 'Power-on' }; if ($s -band 2) { $set += 'SUPERVISOR' }; if ($s -band 4) { $set += 'Hard-disk' }; if ($s -band 64) { $set += 'System-management' }
                if ($s -eq 0) { Add-R $cat 'Lenovo BIOS passwords' PASS 'No BIOS passwords are set (read from Lenovo firmware).' }
                elseif ($s -band 2 -or $s -band 64) { Add-R $cat 'Lenovo BIOS passwords' FAIL ("Passwords set: " + ($set -join ', ') + " (state $s)") 'A ThinkPad supervisor/system-management password is extremely hard to remove. Do NOT buy unless the seller removes it in front of you.' }
                else { Add-R $cat 'Lenovo BIOS passwords' WARN ("Passwords set: " + ($set -join ', ') + " (state $s)") 'Ask the seller to remove them in the BIOS before you pay.' }
            } else { Add-R $cat 'Lenovo BIOS passwords' MANUAL 'Could not read the BIOS password state from Windows (older model or not admin).' 'Enter the BIOS (see above) and confirm it opens without a password and Security > Password shows nothing set.' }
            $ls = @(Get-Cim Lenovo_BiosSetting 'root\wmi' | Where-Object { $_.CurrentSetting -match 'Computrace|Absolute' } | ForEach-Object { $_.CurrentSetting })
            foreach ($x in $ls) {
                if ($x -match ',(Enable|Enabled|Activated)') { Add-R $cat 'Lenovo Absolute/Computrace (BIOS)' FAIL $x 'Anti-theft module is ACTIVATED in the firmware.' }
                else { Add-R $cat 'Lenovo Absolute/Computrace (BIOS)' PASS $x }
            }
        }
        'HP' {
            $hp = @(Get-Cim HP_BIOSPassword 'root\HP\InstrumentedBIOS')
            if ($hp.Count) {
                $setPw = @($hp | Where-Object { $_.IsSet -eq 1 } | ForEach-Object { $_.Name })
                if ($setPw.Count) { Add-R $cat 'HP BIOS passwords' FAIL ('Set: ' + ($setPw -join ', ')) 'A BIOS setup/power-on password is set. The seller must remove it before you pay; HP admin passwords cannot be easily reset.' }
                else { Add-R $cat 'HP BIOS passwords' PASS 'No BIOS passwords set (read from HP firmware).' }
            } else { Add-R $cat 'HP BIOS passwords' MANUAL 'Could not read the HP BIOS password state from Windows.' 'Press Esc then F10 at power-on and make sure the BIOS opens without a password.' }
            $hs = @(Get-Cim HP_BIOSSetting 'root\HP\InstrumentedBIOS' | Where-Object { $_.Name -match 'Absolute|Computrace|LoJack|Ownership Tag|Asset Tracking Number|Enhanced BIOS Authentication|Sure Admin' })
            foreach ($x in $hs) {
                $v = "$($x.CurrentValue)"; if (-not $v) { $v = "$($x.Value)" }
                $line = "$($x.Name) = $v"
                if ($x.Name -match 'Absolute|Computrace|LoJack' -and $v -match 'Active|Enable' -and $v -notmatch 'Inactive|Disable') { Add-R $cat 'HP Absolute Persistence (BIOS)' FAIL $line 'Anti-theft module is active in firmware.' }
                elseif ($x.Name -match 'Ownership Tag|Asset Tracking' -and $v.Trim() -and $v -notmatch '^\s*$') { Add-R $cat "HP $($x.Name)" WARN $line 'Often contains the owning company''s name.' }
                elseif ($x.Name -match 'Enhanced BIOS Authentication|Sure Admin' -and $v -match 'Enable|On') { Add-R $cat 'HP Sure Admin' FAIL $line 'BIOS is locked by HP Sure Admin (company key).' }
                else { Add-R $bcat "HP: $($x.Name)" INFO $line }
            }
        }
        'Dell' {
            $dp = @(Get-Cim PasswordObject 'root\dcim\sysman\wmisecurity')
            if ($dp.Count) {
                $setPw = @($dp | Where-Object { $_.IsPasswordSet -eq 1 } | ForEach-Object { $_.NameId })
                if ($setPw.Count) { Add-R $cat 'Dell BIOS passwords' FAIL ('Set: ' + ($setPw -join ', ')) 'A Dell BIOS/system password is set. The seller must remove it in front of you.' }
                else { Add-R $cat 'Dell BIOS passwords' PASS 'No BIOS passwords set (read from Dell firmware).' }
            } else { Add-R $cat 'Dell BIOS passwords' MANUAL 'Could not read the Dell BIOS password state from Windows (older model or not admin).' 'Press F2 at the Dell logo and confirm the BIOS opens with no password.' }
            $de = @(Get-Cim EnumerationAttribute 'root\dcim\sysman\biosattributes' | Where-Object { $_.AttributeName -match 'Absolute|Computrace' })
            foreach ($x in $de) {
                $line = "$($x.AttributeName) = $($x.CurrentValue)"
                if ("$($x.CurrentValue)" -match 'Enable|Activ' -and "$($x.CurrentValue)" -notmatch 'Disable') { Add-R $cat 'Dell Absolute (BIOS)' FAIL $line 'Anti-theft module is enabled in the firmware.' } else { Add-R $cat 'Dell Absolute (BIOS)' PASS $line }
            }
            $dsx = @(Get-Cim StringAttribute 'root\dcim\sysman\biosattributes' | Where-Object { $_.AttributeName -match 'Asset|Ownership|Property' -and "$($_.CurrentValue)".Trim() })
            foreach ($x in $dsx) { Add-R $cat "Dell $($x.AttributeName)" WARN "$($x.AttributeName) = $($x.CurrentValue)" 'Ownership / asset text set in the BIOS - usually a company name.' }
        }
        'Microsoft' {
            Add-R $cat 'Surface Enterprise Management Mode (SEMM)' MANUAL 'Windows cannot reliably read SEMM.' 'Open Surface UEFI (Volume-Up + Power). If you see a "Management" / SEMM / certificate page, the device is company-locked.'
        }
        'Apple' {
            Add-R $cat 'Apple Activation Lock' MANUAL 'This is a Mac running Windows (Boot Camp).' 'Boot into macOS and confirm Find My Mac and Activation Lock are OFF, and there is no firmware password. A locked Mac is worthless.'
        }
        default {
            Add-R $cat 'BIOS / UEFI password' MANUAL 'This brand does not expose the BIOS password state to Windows.' 'Enter the BIOS (see above) and make sure it opens without asking for a password.'
        }
    }
}

Invoke-Section 'Battery & charger' {
    $cat = 'Battery'
    $bat = @(Get-Cim Win32_Battery)
    if ($bat.Count -eq 0) {
        if ($script:IsLaptop) { Add-R $cat 'Battery present' FAIL 'This is a laptop but Windows cannot see any battery.' 'The battery is dead, disconnected or removed. Price in a replacement.' }
        else { Add-R $cat 'Battery' INFO 'No battery - this looks like a desktop PC.' }
        $script:OnAC = $true
        return
    }
    $xmlPath = Join-Path $script:RawDir 'battery-report.xml'
    $null = & powercfg.exe /batteryreport /output (Join-Path $script:OutDir 'battery-report.html') 2>&1
    $null = & powercfg.exe /batteryreport /xml /output $xmlPath 2>&1
    $list = @()
    if (Test-Path $xmlPath) {
        try {
            [xml]$x = Get-Content $xmlPath -Raw
            foreach ($b in @($x.BatteryReport.Batteries.Battery)) { if ($b) { $list += [pscustomobject]@{ Name = "$($b.Manufacturer) $($b.Id)"; Maker = "$($b.Manufacturer)".Trim(); Id = "$($b.Id)".Trim(); MadeOn = "$($b.ManufactureDate)"; Chem = $b.Chemistry; Design = [double]$b.DesignCapacity; Full = [double]$b.FullChargeCapacity; Cycles = [int]$b.CycleCount } } }
        } catch {}
    }
    if ($list.Count -eq 0) {
        $sd = @(Get-Cim BatteryStaticData 'root\wmi'); $fc = @(Get-Cim BatteryFullChargedCapacity 'root\wmi'); $cc = @(Get-Cim BatteryCycleCount 'root\wmi')
        for ($i = 0; $i -lt $sd.Count; $i++) { $list += [pscustomobject]@{ Name = "Battery $($i+1)"; Chem = ''; Design = [double]$sd[$i].DesignedCapacity; Full = [double]$(if ($fc.Count -gt $i) { $fc[$i].FullChargedCapacity } else { 0 }); Cycles = [int]$(if ($cc.Count -gt $i) { $cc[$i].CycleCount } else { 0 }) } }
    }
    $script:BatList = @($list)
    foreach ($b in $list) {
        if ($b.Design -le 0) { Add-R $cat "Battery health ($($b.Name))" WARN 'The battery does not report its capacity.' 'Battery may be non-original or faulty. Check with the battery report / maker diagnostics.'; continue }
        $h = [math]::Round(100 * $b.Full / $b.Design, 1)
        if (-not $script:Metrics.Contains('BatteryHealth')) { $script:Metrics['BatteryHealth'] = $h; $script:Metrics['BatteryCycles'] = $b.Cycles; $script:Metrics['BatteryFull_mWh'] = $b.Full }
        $d = ("Health: {0}% of original capacity`nDesign capacity: {1:N0} mWh`nFull charge now: {2:N0} mWh`nCharge cycles: {3}`nChemistry: {4}" -f $h, $b.Design, $b.Full, $(if ($b.Cycles -gt 0) { $b.Cycles } else { 'not reported' }), $b.Chem)
        if ($h -ge 80) { Add-R $cat 'Battery health' PASS $d }
        elseif ($h -ge 60) { Add-R $cat 'Battery health' WARN $d 'Battery is worn - expect noticeably shorter run time. Use it to negotiate the price.' }
        else { Add-R $cat 'Battery health' FAIL $d 'Battery is badly worn and will need replacing soon. Price this in.' }
        if ($b.Cycles -gt 800) { Add-R $cat 'Battery charge cycles' WARN "$($b.Cycles) cycles." 'High cycle count - near the end of a typical battery life (500-1000 cycles).' }
    }
    $bs = Get-Cim BatteryStatus 'root\wmi' | Select-Object -First 1
    $pct = $bat[0].EstimatedChargeRemaining
    $onAC = [bool]$bs.PowerOnline
    Add-R $cat 'Current charge' INFO ("Charge: $pct%  On charger: $onAC  Charging: $($bs.Charging)  Rate: $($bs.ChargeRate) mW in / $($bs.DischargeRate) mW out")
    if ($pct -ne $null -and $pct -le 5) { Add-R $cat 'Very low charge' WARN "Battery is at $pct%." 'A battery that is always kept flat can be damaged. Let it charge a while and watch it rises.' }

    if (-not $NoPrompt -and $bs) {
        Write-Host ''
        if ($onAC) {
            [void](Read-Host '   >> UNPLUG the charger now, then press Enter')
            Start-Sleep -Seconds 4
            $b1 = Get-Cim BatteryStatus 'root\wmi' | Select-Object -First 1
            if (-not $b1.PowerOnline -and $b1.Discharging) { Add-R $cat 'Runs on battery' PASS ("Laptop kept running on battery. Power draw: {0:N1} W" -f ($b1.DischargeRate / 1000)) }
            elseif ($b1.PowerOnline) { Add-R $cat 'Runs on battery' WARN 'Windows still thinks the charger is connected.' 'Maybe it was not unplugged - or the charger detection is faulty.' }
            else { Add-R $cat 'Runs on battery' INFO 'Unplugged, but discharge was not confirmed.' }
            if ($script:WantRuntime -and -not $b1.PowerOnline) {
                Write-Host '   measuring battery drain for 2 minutes - leave the laptop alone (screen on)...' -ForegroundColor DarkGray
                $rates = @(); $p0 = (Get-Cim Win32_Battery | Select-Object -First 1).EstimatedChargeRemaining
                for ($i = 0; $i -lt 24; $i++) { Start-Sleep -Seconds 5; $bx = Get-Cim BatteryStatus 'root\wmi' | Select-Object -First 1; if ($bx.DischargeRate -gt 0) { $rates += [double]$bx.DischargeRate } }
                $p1 = (Get-Cim Win32_Battery | Select-Object -First 1).EstimatedChargeRemaining
                $fullNow = ($list | Select-Object -First 1).Full
                if ($rates.Count -and $fullNow -gt 0) {
                    $avgW = ($rates | Measure-Object -Average).Average / 1000
                    $hrs = ($fullNow / 1000) / $avgW
                    $d = ("Average power use at idle: {0:N1} W`nEstimated run-time on a full charge at this load: {1:N1} hours`nCharge went {2}% -> {3}% in 2 minutes" -f $avgW, $hrs, $p0, $p1)
                    if ($hrs -lt 2) { Add-R $cat 'Battery run-time' WARN $d 'Short run-time even at idle. A worn battery, high screen brightness, or a background process using power (check Task Manager).' }
                    else { Add-R $cat 'Battery run-time' PASS $d 'Real-world use (browsing, video) is usually 30-60% of this idle estimate.' }
                } else { Add-R $cat 'Battery run-time' INFO 'The battery does not report its drain rate, so run-time could not be estimated.' }
            }
            [void](Read-Host '   >> PLUG the charger back in, then press Enter')
            Start-Sleep -Seconds 6
        } else {
            [void](Read-Host '   >> PLUG IN the charger now, then press Enter')
            Start-Sleep -Seconds 6
        }
        $b2 = Get-Cim BatteryStatus 'root\wmi' | Select-Object -First 1
        $pct2 = (Get-Cim Win32_Battery | Select-Object -First 1).EstimatedChargeRemaining
        if ($b2.PowerOnline) {
            if ($b2.Charging) { Add-R $cat 'Charger & charging port' PASS ("Charger detected and battery is charging at about {0:N1} W." -f ($b2.ChargeRate / 1000)) 'Also check the charger wattage label matches the original spec and the plug does not wiggle loose.' }
            elseif ($pct2 -ge 95) { Add-R $cat 'Charger & charging port' PASS "Charger detected (battery full: $pct2%)." }
            else { Add-R $cat 'Charger & charging port' WARN "Charger detected but the battery is NOT charging (at $pct2%)." 'Can be a battery-care setting (e.g. charge limit 60/80%) - otherwise a weak/wrong charger or failing battery. Check the maker app.' }
        } else { Add-R $cat 'Charger & charging port' FAIL 'Charger NOT detected after plugging in.' 'Faulty charger, cable or charging port. Try again, check the plug, and try another socket.' }
        $b2 = Get-Cim BatteryStatus 'root\wmi' | Select-Object -First 1
        $onAC = [bool]$b2.PowerOnline
    } else { Add-R $cat 'Charger & charging port' MANUAL 'Not tested automatically.' 'Unplug and re-plug the charger; check Windows shows it charging.' }
    $script:OnAC = $onAC
    Add-R $cat 'Battery report' INFO 'Full Windows battery report saved as battery-report.html in the report folder (capacity history and usage).'
    Add-R $cat 'Swollen battery (physical)' MANUAL 'Look at the laptop from the side on a flat table.' 'Bulging base, lifted touchpad, hard-to-click touchpad, or a lid that does not close flat = swollen battery (fire risk). Do not buy without replacing it.'
}

Invoke-Section 'Storage drives' {
    $cat = 'Storage'
    $pds = @(); try { $pds = @(Get-PhysicalDisk -ErrorAction Stop) } catch {}
    $internalBytes = 0
    $pf = @(Get-Cim MSStorageDriver_FailurePredictStatus 'root\wmi' | Where-Object { $_.PredictFailure })
    if ($pf.Count) { Add-R $cat 'SMART failure prediction' FAIL "$($pf.Count) drive(s) report that failure is predicted." 'A drive is about to fail. Back out or price in a new drive.' }
    foreach ($d in $pds) {
        $label = "$($d.FriendlyName) - $($d.MediaType) / $($d.BusType), $(Format-GB $d.Size)"
        if ("$($d.BusType)" -eq 'USB') { Add-R $cat "USB drive: $($d.FriendlyName)" INFO "$label (probably your test USB stick - ignored)"; continue }
        $internalBytes += [double]$d.Size
        $rc = $null; try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
        $lines = @("Health: $($d.HealthStatus)   Status: $($d.OperationalStatus)")
        if ($rc -and -not $script:Metrics.Contains('DriveWear')) { $script:Metrics['DriveWear'] = $rc.Wear; $script:Metrics['DrivePowerOnHours'] = $rc.PowerOnHours; $script:Metrics['DriveTempC'] = $rc.Temperature }
        if ($rc) {
            if ($rc.Wear -ne $null) { $lines += "Wear (life used): $($rc.Wear)%" }
            if ($rc.Temperature) { $lines += "Temperature: $($rc.Temperature) C (max seen $($rc.TemperatureMax) C)" }
            if ($rc.PowerOnHours) { $lines += ("Powered-on hours: {0:N0} (~{1:N1} years of 24/7)" -f $rc.PowerOnHours, ($rc.PowerOnHours / 8760)) }
            if ($rc.StartStopCycleCount) { $lines += "Power cycles: $($rc.StartStopCycleCount)" }
            $lines += "Read errors: $($rc.ReadErrorsTotal) (uncorrected $($rc.ReadErrorsUncorrected))  Write errors: $($rc.WriteErrorsTotal) (uncorrected $($rc.WriteErrorsUncorrected))"
        } elseif (-not $script:IsAdmin) { $lines += 'Detailed SMART data needs administrator rights.' }
        $det = $lines -join "`n"
        $status = 'PASS'; $adv = ''
        if ("$($d.HealthStatus)" -ne 'Healthy') { $status = 'FAIL'; $adv = 'Windows marks this drive as unhealthy. It may fail soon.' }
        elseif ($rc -and $rc.Wear -ge 90) { $status = 'FAIL'; $adv = 'SSD is almost worn out.' }
        elseif ($rc -and ($rc.ReadErrorsUncorrected -gt 0 -or $rc.WriteErrorsUncorrected -gt 0)) { $status = 'FAIL'; $adv = 'The drive has uncorrectable errors - data loss risk.' }
        elseif ($rc -and $rc.Wear -ge 50) { $status = 'WARN'; $adv = 'SSD has used more than half its rated life.' }
        elseif ($rc -and $rc.Temperature -ge 70) { $status = 'WARN'; $adv = 'Drive runs hot.' }
        elseif ($rc -and $rc.PowerOnHours -gt 30000) { $status = 'WARN'; $adv = 'Very high usage hours.' }
        if ("$($d.MediaType)" -eq 'HDD' -and $script:IsLaptop) { if ($status -eq 'PASS') { $status = 'INFO' }; $adv = ($adv + ' This laptop uses a slow spinning hard drive (HDD) - an SSD upgrade is strongly recommended.').Trim() }
        Add-R $cat "Drive: $label" $status $det $adv
        $kind = if ("$($d.MediaType)" -eq 'HDD') { 'hard drive (HDD)' } elseif ("$($d.BusType)" -eq 'NVMe') { 'NVMe SSD' } else { 'SSD' }
        $hl = "$($d.HealthStatus)"; if ($rc -and $null -ne $rc.Wear) { $hl += ", $($rc.Wear)% wear" }; if ($rc -and $rc.PowerOnHours) { $hl += ", {0:N0} hours used" -f $rc.PowerOnHours }
        $script:SpecDrives += [pscustomobject]@{ Label = ("{0} {1}" -f (Format-GB $d.Size), $kind); Health = $hl; Status = $status; Model = "$($d.FriendlyName)" }
        $script:DriveModels += "$($d.FriendlyName)"
    }
    if ($pds.Count -eq 0) {
        foreach ($d in @(Get-Cim Win32_DiskDrive)) { if ($d.InterfaceType -ne 'USB') { $internalBytes += [double]$d.Size; Add-R $cat "Drive: $($d.Model)" $(if ($d.Status -eq 'OK') { 'PASS' } else { 'FAIL' }) "Status: $($d.Status), size $(Format-GB $d.Size)" } }
    }
    Add-R $cat 'Total internal storage' INFO ("{0} (decimal GB; Windows shows less because it counts in GiB)" -f (Format-GB $internalBytes))
    if ($script:Adv.Storage -match '^\s*(\d+(\.\d+)?)') {
        $adv = [double]$Matches[1]; if ($adv -le 8) { $adv = $adv * 1000 }
        $act = $internalBytes / 1e9
        if ($act -ge $adv * 0.9) { Add-R $cat 'Storage matches advert' PASS ("Advertised {0:N0} GB, found {1:N0} GB." -f $adv, $act) }
        else { Add-R $cat 'Storage matches advert' FAIL ("Advertised {0:N0} GB, but only {1:N0} GB found." -f $adv, $act) 'The drive is smaller than advertised - it may have been swapped.' }
    }
    foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })) {
        $freePct = if ($v.Size) { [math]::Round(100 * $v.SizeRemaining / $v.Size) } else { 0 }
        $st = 'PASS'; if ("$($v.HealthStatus)" -ne 'Healthy') { $st = 'FAIL' } elseif ($freePct -lt 10) { $st = 'WARN' }
        Add-R $cat "Volume $($v.DriveLetter):" $st ("{0} {1}, {2} free of {3} ({4}%), health: {5}" -f $v.FileSystemLabel, $v.FileSystem, (Format-GB $v.SizeRemaining), (Format-GB $v.Size), $freePct, $v.HealthStatus)
    }
    $dirty = (& fsutil.exe dirty query $env:SystemDrive 2>&1 | Out-String)
    if ($dirty -match 'is Dirty|ist fehlerhaft|est sale') { Add-R $cat 'File system dirty flag' WARN $dirty.Trim() 'Windows wants to repair the file system at next boot - possible disk problems or improper shutdowns.' }
    if ($script:IsAdmin) {
        $job = Start-Job -ScriptBlock { param($dl) try { (Repair-Volume -DriveLetter $dl -Scan -ErrorAction Stop | Out-String).Trim() } catch { 'ERROR: ' + $_.Exception.Message } } -ArgumentList ($env:SystemDrive.TrimEnd(':'))
        if (Wait-Job $job -Timeout 180) {
            $r = Receive-Job $job
            if ($r -match 'NoErrorsFound') { Add-R $cat 'File system scan (C:)' PASS 'Online file-system scan found no errors.' }
            elseif ($r -match '^ERROR') { Add-R $cat 'File system scan (C:)' INFO $r }
            else { Add-R $cat 'File system scan (C:)' WARN "Result: $r" 'File system errors found. Run "chkdsk C: /f" and check the drive health.' }
        } else { Stop-Job $job; Add-R $cat 'File system scan (C:)' INFO 'Scan took longer than 3 minutes and was skipped.' }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Section 'Memory (RAM)' {
    $cat = 'Memory'
    $mods = @(Get-Cim Win32_PhysicalMemory)
    $total = ($mods | Measure-Object -Property Capacity -Sum).Sum
    $slots = (Get-Cim Win32_PhysicalMemoryArray | Measure-Object -Property MemoryDevices -Sum).Sum
    $types = @{ 20 = 'DDR'; 21 = 'DDR2'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
    $lines = foreach ($m in $mods) { "{0}: {1:N0} GB {2} {3} MHz  {4} {5}" -f $m.DeviceLocator, ($m.Capacity / 1GB), $types[[int]$m.SMBIOSMemoryType], $(if ($m.ConfiguredClockSpeed) { $m.ConfiguredClockSpeed } else { $m.Speed }), "$($m.Manufacturer)".Trim(), "$($m.PartNumber)".Trim() }
    $gb = [math]::Round($total / 1GB)
    $vis = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $rt = @($mods | ForEach-Object { $types[[int]$_.SMBIOSMemoryType] } | Where-Object { $_ } | Select-Object -Unique) -join '/'
    $spd = ($mods | ForEach-Object { if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed } } | Measure-Object -Maximum).Maximum
    $layout = (@($mods | ForEach-Object { [math]::Round($_.Capacity / 1GB) } | Group-Object | ForEach-Object { "$($_.Count) x $($_.Name) GB" }) -join ' + ')
    $script:Spec['RAM'] = ("$gb GB $rt" + $(if ($spd) { " $spd MHz" }) + $(if ($mods.Count -gt 1) { " ($layout)" })).Replace('  ', ' ')
    $script:RamMods = $mods
    Add-R $cat 'Installed RAM' INFO ("Total: $gb GB in $($mods.Count) module(s), $slots slot(s) reported. Usable by Windows: $vis GB`n" + ($lines -join "`n"))
    if ($mods.Count -eq 1 -and $slots -ge 2) { Add-R $cat 'Memory channels' INFO 'Only one memory module is fitted although there are 2+ slots.' 'Runs in single-channel mode (slower, especially for graphics). Easy to upgrade later.' }
    if ($gb -gt 0 -and $vis -lt ($gb * 0.7)) { Add-R $cat 'Usable memory' WARN "$gb GB installed but only $vis GB usable." 'A lot is reserved - could be integrated graphics settings or a faulty module/slot.' }
    if ($script:Adv.Ram -match '^\s*(\d+)') {
        $a = [int]$Matches[1]
        if ($gb -ge $a) { Add-R $cat 'RAM matches advert' PASS "Advertised $a GB, found $gb GB." } else { Add-R $cat 'RAM matches advert' FAIL "Advertised $a GB, but only $gb GB installed." 'Less memory than advertised.' }
    }
    if ($gb -lt 8) { Add-R $cat 'Amount of RAM' WARN "$gb GB is low for Windows 11 today." '16 GB is recommended; 8 GB is the practical minimum.' }
    $md = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } 5
    if ($md.Count) { $e = $md[0]; Add-R $cat 'Last Windows Memory Diagnostic' $(if ($e.Id -eq 1201) { 'PASS' } else { 'FAIL' }) ("{0}: {1}" -f $e.TimeCreated, (Short $e.Message 200)) }
    Add-R $cat 'Full memory test' MANUAL 'The quick RAM test below only checks part of the memory while Windows runs.' 'For a full test run "Windows Memory Diagnostic" (mdsched.exe - restarts, ~20 min) or MemTest86 from USB.'
}

Invoke-Section 'Processor, graphics & screen' {
    $cpus = @(Get-Cim Win32_Processor)
    foreach ($c in $cpus) { Add-R 'Processor' 'CPU' INFO ("{0}`n{1} cores / {2} threads, base {3} MHz" -f "$($c.Name)".Trim(), $c.NumberOfCores, $c.NumberOfLogicalProcessors, $c.MaxClockSpeed) }
    $script:CpuName = "$($cpus[0].Name)".Trim()
    $script:CpuThreads = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $script:CpuBase = [double]$cpus[0].MaxClockSpeed
    if ($script:Adv.Cpu) {
        if (Test-Advertised $script:Adv.Cpu @($script:CpuName)) { Add-R 'Processor' 'CPU matches advert' PASS "Advertised: $($script:Adv.Cpu)`nFound: $($script:CpuName)" }
        else { Add-R 'Processor' 'CPU matches advert' FAIL "Advertised: $($script:Adv.Cpu)`nFound: $($script:CpuName)" 'The processor is different from the advert.' }
    }
    $cat = 'Graphics'
    $vram = @{}
    foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })) {
        $p = Get-RegProps $k.PSPath
        if (-not $p) { continue }
        $q = $p.'HardwareInformation.qwMemorySize'
        if (-not $q) { $q = $p.'HardwareInformation.MemorySize'; if ($q -is [byte[]] -and $q.Length -ge 4) { $q = [BitConverter]::ToUInt32($q, 0) } }
        if ($p.DriverDesc -and $q) { $vram["$($p.DriverDesc)"] = [double]$q }
    }
    $gpus = @(Get-Cim Win32_VideoController)
    $names = @()
    foreach ($g in $gpus) {
        $names += $g.Name
        if ($g.Name -notmatch 'Basic Display|Basic Render|Remote|Virtual|Parsec|Meta Virtual|IddCx') { $script:GpuNames += $g.Name }
        if (-not $script:Spec['Res'] -and $g.CurrentHorizontalResolution) { $script:Spec['Res'] = "$($g.CurrentHorizontalResolution) x $($g.CurrentVerticalResolution)"; $script:Spec['Hz'] = $g.CurrentRefreshRate }
        $mem = if ($vram.ContainsKey("$($g.Name)")) { $vram["$($g.Name)"] } else { [double]$g.AdapterRAM }
        $dd = ''; if ($g.DriverDate) { $dd = $g.DriverDate.ToString('yyyy-MM-dd') }
        $d = "Driver $($g.DriverVersion) ($dd)`nVideo memory: $('{0:N1}' -f ($mem / 1GB)) GB`nStatus: $($g.Status), device error code: $($g.ConfigManagerErrorCode)`nCurrent mode: $($g.CurrentHorizontalResolution) x $($g.CurrentVerticalResolution) @ $($g.CurrentRefreshRate) Hz"
        if ($g.ConfigManagerErrorCode -eq 43) { Add-R $cat "GPU: $($g.Name)" FAIL $d 'Error 43: Windows stopped this graphics chip because it reported a problem. Classic sign of a failing GPU.' }
        elseif ($g.ConfigManagerErrorCode -eq 22) { Add-R $cat "GPU: $($g.Name)" WARN $d 'This graphics chip has been DISABLED in Device Manager. Why? Enable it and test - it may have been disabled to hide a fault.' }
        elseif ($g.ConfigManagerErrorCode -and $g.ConfigManagerErrorCode -ne 0) { Add-R $cat "GPU: $($g.Name)" FAIL $d 'The graphics device has an error.' }
        elseif ($g.Name -match 'Basic Display|Basic Render') { Add-R $cat "GPU: $($g.Name)" WARN $d 'No proper graphics driver is installed.' }
        else { Add-R $cat "GPU: $($g.Name)" PASS $d }
    }
    $smi = @("$env:SystemRoot\System32\nvidia-smi.exe", "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($smi) { $o = (& $smi --query-gpu=name,temperature.gpu,memory.total,power.draw,pcie.link.gen.max,pcie.link.width.max --format=csv,noheader 2>&1 | Out-String).Trim(); if ($o) { Add-R $cat 'NVIDIA details' INFO "name, temp C, memory, power, PCIe gen, width:`n$o" } }
    if ($script:Adv.Gpu) {
        if (Test-Advertised $script:Adv.Gpu $names) { Add-R $cat 'GPU matches advert' PASS "Advertised: $($script:Adv.Gpu)`nFound: $($names -join ', ')" }
        else { Add-R $cat 'GPU matches advert' FAIL "Advertised: $($script:Adv.Gpu)`nFound: $($names -join ', ')" 'The advertised graphics card was not found. It may be missing, dead, disabled in BIOS or not the model claimed.' }
    }
    $cat = 'Screen'
    $ids = @(Get-Cim WmiMonitorID 'root\wmi'); $par = @(Get-Cim WmiMonitorBasicDisplayParams 'root\wmi'); $con = @(Get-Cim WmiMonitorConnectionParams 'root\wmi')
    foreach ($m in $ids) {
        $nm = -join (@($m.UserFriendlyName) | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
        $mf = -join (@($m.ManufacturerName) | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
        $pc = -join (@($m.ProductCodeID) | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
        $pp = $par | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        $cc = $con | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        $size = ''; if ($pp -and $pp.MaxHorizontalImageSize) { $size = '{0:N1} inch' -f ([math]::Sqrt([math]::Pow($pp.MaxHorizontalImageSize, 2) + [math]::Pow($pp.MaxVerticalImageSize, 2)) / 2.54) }
        $internal = ($cc -and ([int64]$cc.VideoOutputTechnology -eq 2147483648 -or [int64]$cc.VideoOutputTechnology -eq -2147483648))
        if ($internal -and $size) { $script:Spec['ScreenSize'] = $size }
        Add-R $cat $(if ($internal) { 'Built-in display' } else { 'Display' }) INFO "Panel: $mf $pc $nm  Size: $size  Year: $($m.YearOfManufacture)"
    }
    Add-R $cat 'Dead pixels / backlight / touch' MANUAL 'Open ManualTests.html > Screen test.' 'Look for dead or stuck pixels, bright patches at the edges (backlight bleed), lines, yellow tint, flicker at low brightness. Test brightness keys.'
}

Invoke-Section 'Wi-Fi & Bluetooth' {
    $cat = 'Wireless'
    $radios = $null
    try {
        $null = [Windows.Devices.Radios.Radio, Windows.System.Devices, ContentType = WindowsRuntime]
        $radios = Invoke-WinRtAwait ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]]) 8000
    } catch {}
    $wifi = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -match '802\.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11' })
    if ($wifi.Count -eq 0) { Add-R $cat 'Wi-Fi adapter' $(if ($script:IsLaptop) { 'FAIL' } else { 'INFO' }) 'No Wi-Fi adapter found.' 'It may be disabled in BIOS, missing, or broken.' }
    foreach ($w in $wifi) {
        $drv = (& netsh.exe wlan show drivers 2>&1 | Out-String)
        $std = 'unknown'
        if ($drv -match '802\.11be') { $std = 'Wi-Fi 7 (802.11be)' } elseif ($drv -match '802\.11ax') { $std = 'Wi-Fi 6/6E (802.11ax)' } elseif ($drv -match '802\.11ac') { $std = 'Wi-Fi 5 (802.11ac)' } elseif ($drv -match '802\.11n') { $std = 'Wi-Fi 4 (802.11n)' }
        $nets = (& netsh.exe wlan show networks 2>&1 | Out-String)
        $count = ([regex]::Matches($nets, '(?m)^SSID \d+ :')).Count
        $d = "$($w.InterfaceDescription)`nStatus: $($w.Status)   Standard: $std   Driver: $($w.DriverVersion)`nNetworks visible right now: $count"
        if ($std -ne 'unknown') { $script:Spec['WiFi'] = $std }
        $wr = $radios | Where-Object { "$($_.Kind)" -eq 'WiFi' } | Select-Object -First 1
        if ($wr) { $d += "`nRadio: $($wr.State)" }
        if ("$($w.Status)" -eq 'Disabled') { Add-R $cat 'Wi-Fi' WARN $d 'Wi-Fi adapter is disabled - enable it and test.' }
        elseif ($count -gt 0 -or "$($w.Status)" -eq 'Up') { Add-R $cat 'Wi-Fi' PASS $d 'Connect to a network (e.g. your phone hotspot) and open a website to be sure.' }
        else { Add-R $cat 'Wi-Fi' WARN $d 'No networks seen (Windows may need Location turned on to list networks). Connect to your phone hotspot to test.' }
    }
    $bt = @($script:Pnp | Where-Object { $_.Class -eq 'Bluetooth' })
    $btRadio = @($bt | Where-Object { $_.InstanceId -match '^(USB|PCI|ACPI|UART)\\' -or $_.FriendlyName -match 'Bluetooth.*(Radio|Adapter|Wireless)|Wireless Bluetooth|Intel.*Bluetooth|Realtek.*Bluetooth|Qualcomm.*Bluetooth|MediaTek.*Bluetooth' })
    $paired = @($bt | Where-Object { $_.InstanceId -match '^BTH(ENUM|LE)\\DEV_' })
    $svc = $script:Services | Where-Object { $_.Name -eq 'bthserv' } | Select-Object -First 1
    $br = $radios | Where-Object { "$($_.Kind)" -eq 'Bluetooth' } | Select-Object -First 1
    if ($btRadio.Count -eq 0 -and -not $br) { Add-R $cat 'Bluetooth' $(if ($script:IsLaptop) { 'FAIL' } else { 'INFO' }) 'No Bluetooth adapter found.' 'Bluetooth missing, disabled in BIOS/Device Manager, or broken.' }
    else {
        $bad = @($btRadio | Where-Object { $_.Status -ne 'OK' })
        $d = "Adapter: $(($btRadio | ForEach-Object { $_.FriendlyName + ' [' + $_.Status + ']' }) -join '; ')`nRadio state: $(if ($br) { $br.State } else { 'unknown' })`nBluetooth service: $($svc.State)`nRemembered (paired) device entries: $($paired.Count)"
        if ($bad.Count) { Add-R $cat 'Bluetooth' FAIL $d 'The Bluetooth adapter has a driver/device error.' }
        elseif ($br -and "$($br.State)" -eq 'Off') { Add-R $cat 'Bluetooth' WARN $d 'Bluetooth is switched OFF. Turn it on and pair your phone or headphones to test.' }
        else { Add-R $cat 'Bluetooth' PASS $d 'Pair your phone or earbuds to confirm it really works.' }
        # try to discover nearby Bluetooth LE devices (phones, watches, earbuds) as proof of a working radio
        try {
            $null = [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType = WindowsRuntime]
            $null = [Windows.Devices.Bluetooth.BluetoothLEDevice, Windows.Devices.Bluetooth, ContentType = WindowsRuntime]
            $sel = [Windows.Devices.Bluetooth.BluetoothLEDevice]::GetDeviceSelectorFromPairingState($false)
            $found = Invoke-WinRtAwait ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($sel)) ([Windows.Devices.Enumeration.DeviceInformationCollection]) 15000
            if ($found -and $found.Count -gt 0) { Add-R $cat 'Bluetooth scan' PASS "Bluetooth found $($found.Count) nearby device(s) - the radio is working." }
            else { Add-R $cat 'Bluetooth scan' MANUAL 'No nearby Bluetooth devices were found by the quick scan.' 'Turn on Bluetooth on your phone, then Settings > Bluetooth & devices > Add device on the laptop.' }
        } catch {}
    }
    $lan = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -eq '802.3' })
    foreach ($l in $lan) { Add-R $cat "Ethernet: $($l.InterfaceDescription)" INFO "Status: $($l.Status)  Speed: $($l.LinkSpeed)" }
    $wwan = @($script:Pnp | Where-Object { $_.Class -in @('Net','Modem','MobileBroadband') -and $_.FriendlyName -match 'Mobile Broadband|WWAN|\bLTE\b|\b5G\b|Snapdragon X\d+ .*Modem|Fibocom|Quectel|Sierra Wireless|Telit' })
    foreach ($m in $wwan) { Add-R $cat "Mobile data modem: $($m.FriendlyName)" INFO "Status: $($m.Status)" 'Has a SIM/4G/5G modem - test with your SIM if you need it (some are carrier-locked).' }
}

Invoke-Section 'Camera, audio, keyboard, touchpad, ports' {
    $cat = 'Other hardware'
    function Show-Dev([string]$Title, $Devs, [bool]$Expected, [string]$Manual) {
        $Devs = @($Devs | Where-Object { $_ })
        if ($Devs.Count -eq 0) { if ($Expected) { Add-R $cat $Title WARN 'Not found.' "Either not fitted, disabled in BIOS/Device Manager or faulty. $Manual" }; return }
        $bad = @($Devs | Where-Object { $_.Status -ne 'OK' })
        $d = ($Devs | ForEach-Object { "$($_.FriendlyName) [$($_.Status)]" } | Select-Object -Unique) -join "`n"
        if ($bad.Count) { Add-R $cat $Title FAIL $d "Device has an error. $Manual" } else { Add-R $cat $Title PASS $d $Manual }
    }
    $L = $script:IsLaptop
    Show-Dev 'Webcam' ($script:Pnp | Where-Object { $_.Class -in @('Camera','Image') -and $_.FriendlyName -notmatch 'scanner|printer' }) $L 'Test it in ManualTests.html > Webcam (or the Camera app).'
    Show-Dev 'Speakers / audio chip' ($script:Pnp | Where-Object { $_.Class -eq 'MEDIA' -and $_.FriendlyName -match 'Audio|Sound|Realtek|Conexant|Cirrus|IDT|Sound Research|Intel.*SST|Smart Sound' }) $true 'Test left/right speakers in ManualTests.html > Speakers.'
    Show-Dev 'Microphone' ($script:Pnp | Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.FriendlyName -match 'Microphone|Mic|Mikrofon|Micro' }) $L 'Test in ManualTests.html > Microphone.'
    Show-Dev 'Keyboard' ($script:Pnp | Where-Object { $_.Class -eq 'Keyboard' }) $true 'Press every key in ManualTests.html > Keyboard.'
    Show-Dev 'Touchpad' ($script:Pnp | Where-Object { $_.Class -in @('Mouse','HIDClass') -and $_.FriendlyName -match 'touch ?pad|Precision|I2C HID|Synaptics|ELAN|Alps|TouchPad' -and $_.FriendlyName -notmatch 'screen' }) $L 'Test clicks, scrolling and two-finger gestures in ManualTests.html > Touchpad.'
    Show-Dev 'Touch screen' ($script:Pnp | Where-Object { $_.FriendlyName -match 'touch ?screen' }) $false 'Draw across the whole screen in ManualTests.html > Touch & pen; watch for dead zones or ghost touches.'
    Show-Dev 'Fingerprint / face sign-in' ($script:Pnp | Where-Object { $_.Class -eq 'Biometric' }) $false 'Set up Windows Hello (Settings > Accounts > Sign-in options) to test.'
    Show-Dev 'SD card reader' ($script:Pnp | Where-Object { $_.FriendlyName -match 'Card ?Reader|SD Host|SDXC|SD Card' }) $false 'Insert an SD card if you need it.'
    Show-Dev 'Thunderbolt / USB4' ($script:Pnp | Where-Object { $_.FriendlyName -match 'Thunderbolt|USB4' }) $false ''
    $usb = @($script:Pnp | Where-Object { $_.Class -eq 'USB' -and $_.FriendlyName -match 'Host Controller|Root Hub|xHCI' })
    Show-Dev 'USB controllers' $usb $true 'Plug this USB stick (or a mouse) into EVERY USB port, one by one, and check each one works. Test HDMI with a TV/monitor if you can, and the headphone jack.'
    $cp = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' 'Value'
    if ($cp -eq 'Deny') { Add-R $cat 'Camera privacy setting' INFO 'Camera access is turned off in Windows privacy settings.' 'Turn it on (Settings > Privacy > Camera) before testing the webcam.' }
}

Invoke-Section 'Device Manager problems' {
    $cat = 'Devices'
    $codes = @{ 1 = 'not configured'; 3 = 'driver corrupted / low memory'; 10 = 'cannot start'; 12 = 'resource conflict'; 14 = 'needs restart'; 18 = 'reinstall drivers'; 19 = 'registry problem'; 21 = 'being removed'; 22 = 'DISABLED by someone'; 24 = 'not present / not working'; 28 = 'no driver installed'; 29 = 'disabled by firmware/BIOS'; 31 = 'driver failed'; 32 = 'driver service disabled'; 37 = 'driver failed to initialise'; 39 = 'driver missing/corrupt'; 41 = 'driver loaded but device not found'; 43 = 'device reported a FAULT'; 48 = 'driver blocked'; 52 = 'driver signature problem' }
    $bad = @(Get-Cim Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 45 })
    $rows = foreach ($b in $bad) { [pscustomobject]@{ Device = $b.Name; Class = $b.PNPClass; Code = $b.ConfigManagerErrorCode; Meaning = $codes[[int]$b.ConfigManagerErrorCode]; Id = $b.PNPDeviceID } }
    Add-Appendix 'Devices with problems (Device Manager)' $rows
    $disabled = @($rows | Where-Object { $_.Code -eq 22 -or $_.Code -eq 29 })
    $broken = @($rows | Where-Object { $_.Code -in @(10, 31, 37, 39, 41, 43, 3, 24) })
    $nodrv = @($rows | Where-Object { $_.Code -eq 28 })
    if ($broken.Count) { Add-R $cat 'Faulty devices' FAIL (Join-Lines ($broken | ForEach-Object { "$($_.Device) - code $($_.Code): $($_.Meaning)" })) 'Hardware or driver failures. Find out what each device is - it may be a broken part.' }
    if ($disabled.Count) { Add-R $cat 'Disabled devices' WARN (Join-Lines ($disabled | ForEach-Object { "$($_.Device) ($($_.Class)) - $($_.Meaning)" })) 'Someone disabled these. Sellers sometimes disable a faulty touchscreen, camera or GPU to hide the fault. Re-enable and test.' }
    if ($nodrv.Count) { Add-R $cat 'Devices without drivers' WARN (Join-Lines ($nodrv | ForEach-Object { "$($_.Device) ($($_.Id))" })) 'Missing drivers - usually fixable with Windows Update or the maker''s driver tool.' }
    $other = @($rows | Where-Object { $broken -notcontains $_ -and $disabled -notcontains $_ -and $nodrv -notcontains $_ })
    if ($other.Count) { Add-R $cat 'Other device warnings' INFO (Join-Lines ($other | ForEach-Object { "$($_.Device) - code $($_.Code): $($_.Meaning)" })) }
    if ($rows.Count -eq 0) { Add-R $cat 'Device Manager' PASS 'All devices are working - no errors or disabled devices.' }
}

Invoke-Section 'Crash & hardware error history' {
    $cat = 'Stability'
    $since = (Get-Date).AddDays(-120)
    $oldest = $null; try { $oldest = (Get-WinEvent -LogName System -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch {}
    Add-R $cat 'Log history' INFO ("System log starts: $oldest. Checks below cover the last 120 days." ) $(if ($oldest -and $oldest -gt (Get-Date).AddDays(-7)) { 'The logs are very new (fresh install or cleared logs) so past problems may be hidden.' } else { '' })
    $bsod = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since } 50
    if ($bsod.Count) {
        $l = $bsod | Select-Object -First 10 | ForEach-Object { $code = ''; if ($_.Message -match '(0x[0-9a-fA-F]{8,})') { $code = $Matches[1] }; "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))  bugcheck $code" }
        Add-R $cat 'Blue screens (crashes)' $(if ($bsod.Count -ge 3) { 'FAIL' } else { 'WARN' }) ("$($bsod.Count) blue-screen crash(es):`n" + ($l -join "`n")) 'Repeated blue screens point to bad RAM, drive, overheating or drivers. Ask the seller about it.'
    } else { Add-R $cat 'Blue screens (crashes)' PASS 'No blue-screen crashes logged.' }
    $kp = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } 200
    $us = Get-Events @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $since } 200
    $n = [math]::Max($kp.Count, $us.Count)
    if ($n -ge 5) { Add-R $cat 'Unexpected shutdowns' WARN "$n unexpected power-offs/restarts (Kernel-Power 41 / 6008)." 'Could be overheating, a failing battery/charger, hardware faults - or just someone holding the power button. Ask.' }
    elseif ($n -gt 0) { Add-R $cat 'Unexpected shutdowns' INFO "$n unexpected shutdown(s)." }
    else { Add-R $cat 'Unexpected shutdowns' PASS 'None logged.' }
    $wh = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } 200
    if ($wh.Count) {
        $fatal = @($wh | Where-Object { $_.Level -le 2 })
        $l = $wh | Select-Object -First 8 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd'))  id $($_.Id): $(Short $_.Message 140)" }
        Add-R $cat 'Hardware errors (WHEA)' $(if ($fatal.Count) { 'FAIL' } else { 'WARN' }) ("$($wh.Count) hardware error report(s), $($fatal.Count) serious:`n" + ($l -join "`n")) 'The CPU/RAM/PCIe hardware itself reported errors. Serious sign of failing hardware.'
    } else { Add-R $cat 'Hardware errors (WHEA)' PASS 'No hardware error reports.' }
    $disk = @()
    $disk += Get-Events @{ LogName = 'System'; ProviderName = 'disk'; Id = @(7, 11, 51, 52, 153, 154); StartTime = $since } 200
    $disk += Get-Events @{ LogName = 'System'; ProviderName = 'Ntfs'; Id = @(55); StartTime = $since } 50
    $disk += Get-Events @{ LogName = 'System'; ProviderName = @('stornvme', 'storahci', 'iaStorAC', 'iaStorAVC'); Level = @(1, 2, 3); StartTime = $since } 100
    if ($disk.Count) {
        $l = $disk | Sort-Object TimeCreated -Descending | Select-Object -First 8 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd'))  $($_.ProviderName) $($_.Id): $(Short $_.Message 120)" }
        Add-R $cat 'Disk errors in log' $(if ($disk.Count -ge 5) { 'FAIL' } else { 'WARN' }) ("$($disk.Count) disk/file-system error(s):`n" + ($l -join "`n")) 'Bad sectors, timeouts or file-system corruption. If several are about the internal drive, it may be failing. (Errors about a USB stick can be ignored.)'
    } else { Add-R $cat 'Disk errors in log' PASS 'No disk errors logged.' }
    $thr = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = (Get-Date).AddDays(-30) } 500
    if ($thr.Count -ge 20) { Add-R $cat 'Firmware CPU slow-downs' WARN "$($thr.Count) events in 30 days where the firmware limited the CPU speed." 'Common causes: overheating (dust / dried thermal paste), a weak or wrong charger, or a worn battery.' }
    elseif ($thr.Count) { Add-R $cat 'Firmware CPU slow-downs' INFO "$($thr.Count) CPU speed-limit events in 30 days." }
    $dumps = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue)
    if ($dumps.Count) { Add-R $cat 'Crash dump files' WARN "$($dumps.Count) crash dump(s) in $env:SystemRoot\Minidump, newest $(($dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime)" 'Evidence of past blue screens.' }
}

Invoke-Section 'User accounts & previous owner data' {
    $cat = 'Accounts'
    $users = @(); try { $users = @(Get-LocalUser -ErrorAction Stop) } catch {}
    $machineSid = ''; if ($users.Count) { $machineSid = $users[0].SID.AccountDomainSid.Value }
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name) ($($_.PrincipalSource))" }) }
    catch {
        try {
            $gname = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $g = [ADSI]"WinNT://$env:COMPUTERNAME/$gname,group"
            $admins = @($g.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null) -replace '^WinNT://', '' })
        } catch {}
    }
    $rows = foreach ($u in $users) { [pscustomobject]@{ Name = $u.Name; Enabled = $u.Enabled; Type = [string]$u.PrincipalSource; LastLogon = $u.LastLogon; PasswordRequired = $u.PasswordRequired; Description = $u.Description } }
    Add-Appendix 'Local user accounts' $rows
    Add-R $cat 'Administrators' INFO (Join-Lines $admins) 'Only the people you expect should be administrators.'
    if (@($admins | Where-Object { $_ -match 'AzureAD|S-1-12-1|\\Domain Admins|@' }).Count) { Add-R 'Company lock' 'Company accounts are administrators' FAIL (Join-Lines ($admins | Where-Object { $_ -match 'AzureAD|S-1-12-1|Domain|@' })) 'Company/organisation accounts have admin rights on this PC.' }
    $adm = $users | Where-Object { $_.SID.Value -match '-500$' }
    if ($adm -and $adm.Enabled) { Add-R $cat 'Built-in Administrator account' WARN "The hidden built-in Administrator account ('$($adm.Name)') is ENABLED." 'Normally disabled. Often enabled by tweak tools or after cracks. Reset fixes it.' }
    $gst = $users | Where-Object { $_.SID.Value -match '-501$' }
    if ($gst -and $gst.Enabled) { Add-R $cat 'Guest account' WARN 'The Guest account is enabled.' 'Normally disabled.' }
    $hidden = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if ($hidden) { $h = @($hidden.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -eq 0 } | ForEach-Object { $_.Name }); if ($h.Count) { Add-R $cat 'Hidden user accounts' WARN ("Accounts hidden from the sign-in screen: " + ($h -join ', ')) 'Hidden accounts can be a backdoor. Ask why they exist; a full reset removes them.' } }
    $msa = @($users | Where-Object { "$($_.PrincipalSource)" -eq 'MicrosoftAccount' })
    if ($script:Own) {
        $me = $env:USERNAME
        $others = @($users | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' -and $_.Name -ne $me })
        if ($others.Count) { Add-R $cat 'Other user accounts' WARN ("Accounts other than yours ($me): " + (($others | ForEach-Object { "$($_.Name) ($($_.PrincipalSource), last logon $($_.LastLogon))" }) -join '; ')) 'If these belong to the previous owner, remove them (Settings > Accounts > Other users) - or better, reset the PC.' }
        else { Add-R $cat 'Other user accounts' PASS "Only your account ($me) is active." }
        if ($msa.Count) { Add-R $cat 'Microsoft account' INFO ("Microsoft account(s) on this PC: " + (($msa | ForEach-Object { $_.Name }) -join ', ')) 'Make sure it is YOUR account, then turn on Find My Device (Settings > Privacy & security) and check the PC shows up in account.microsoft.com/devices.' }
        $msa = @()
    }
    if ($script:Sell -and $msa.Count) { Add-R 'Before selling' 'Your Microsoft account is still on this PC' WARN ("Signed in: " + (($msa | ForEach-Object { $_.Name }) -join ', ')) 'Before handing it over: account.microsoft.com/devices > remove this PC, and turn off Find My Device. Otherwise the buyer''s PC stays linked to you (and eBay buyers may report it as locked).'; $msa = @() }
    if ($msa.Count) { Add-R $cat "Seller's Microsoft account" WARN ("Signed in with Microsoft account(s): " + (($msa | ForEach-Object { $_.Name }) -join ', ')) 'Before you take it: the seller must sign out, remove the laptop from account.microsoft.com/devices and turn off Find My Device - otherwise they can still lock or locate it.' }

    $prof = foreach ($p in $script:Profiles) {
        $kind = 'Local'
        if ($p.SID -match '^S-1-12-1-') { $kind = 'Company (Entra ID / Azure AD)' }
        elseif ($machineSid -and $p.SID -notlike "$machineSid-*") { $kind = 'Company DOMAIN account' }
        [pscustomobject]@{ Folder = $p.LocalPath; Kind = $kind; LastUsed = $p.LastUseTime; Loaded = $p.Loaded; SID = $p.SID }
    }
    Add-Appendix 'User profiles on disk' $prof
    $corp = @($prof | Where-Object { $_.Kind -ne 'Local' })
    if ($corp.Count) { Add-R 'Company lock' 'Company user profiles on disk' FAIL (Join-Lines ($corp | ForEach-Object { "$($_.Folder) - $($_.Kind), last used $($_.LastUsed)" })) 'People have signed into this PC with company accounts. It was a company device. Insist on a full reset and proof it was released.' }
    Add-R $cat 'User profiles' INFO ("$(@($prof).Count) user profile(s): " + ((@($prof) | ForEach-Object { Split-Path $_.Folder -Leaf }) -join ', '))
    $data = @()
    $profList = $script:Profiles
    if ($script:Own) { $profList = @($script:Profiles | Where-Object { (Split-Path $_.LocalPath -Leaf) -ne $env:USERNAME }) }
    foreach ($p in $profList) {
        foreach ($sub in 'Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos') {
            $dir = Join-Path $p.LocalPath $sub
            try { $n = @([IO.Directory]::EnumerateFileSystemEntries($dir) | Select-Object -First 200).Count; if ($n -gt 1) { $data += "$dir : $n+ items" } } catch {}
        }
        foreach ($b in @('AppData\Local\Google\Chrome\User Data', 'AppData\Local\Microsoft\Edge\User Data', 'AppData\Roaming\Mozilla\Firefox\Profiles', 'AppData\Local\BraveSoftware\Brave-Browser\User Data')) {
            $bd = Join-Path $p.LocalPath $b
            if (Test-Path -LiteralPath $bd) { $lg = @(Get-ChildItem -LiteralPath $bd -Recurse -Depth 2 -Filter 'Login Data' -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 40000 }); if ($lg.Count) { $data += "$bd : saved browser logins present" } }
        }
    }
    if ($script:Sell) {
        if ($data.Count) { Add-R 'Before selling' 'Your personal files and saved passwords' WARN (Join-Lines $data 15) 'Back them up, then wipe the PC with Reset this PC > Remove everything > Clean data = ON (see the before-selling checklist). Deleting files by hand is NOT enough - they can be recovered.' }
        else { Add-R 'Before selling' 'Personal files' PASS 'No personal files or saved browser passwords found.' }
        $data = @(); $script:SellSkipFiles = $true
    }
    if ($script:SellSkipFiles) { }
    elseif ($data.Count) { Add-R $cat "Previous owner's files" WARN (Join-Lines $data 15) 'The PC has not been wiped. For your safety (and theirs) the PC should be reset to factory before you use it - anything they installed stays otherwise.' }
    elseif ($script:Own) { Add-R $cat "Previous owner's files" PASS 'No leftover files in other user profiles.' }
    else { Add-R $cat "Previous owner's files" PASS 'User folders look empty / freshly set up.' }
    $pairedCount = @($script:Pnp | Where-Object { $_.Class -eq 'Bluetooth' -and $_.InstanceId -match '^BTH(ENUM|LE)\\DEV_' } | ForEach-Object { ($_.InstanceId -split '\\')[1] } | Select-Object -Unique).Count
    if ($pairedCount -gt 0) { Add-R $cat 'Paired Bluetooth devices' INFO "$pairedCount remembered Bluetooth device(s) from the previous owner." }
    $wtmp = Join-Path $script:OutDir '_wlan_tmp'
    try {
        New-Item -ItemType Directory -Path $wtmp -Force | Out-Null
        $null = & netsh.exe wlan export profile folder="$wtmp" 2>&1
        $wl = foreach ($f in @(Get-ChildItem $wtmp -Filter *.xml -ErrorAction SilentlyContinue)) {
            try { [xml]$x = Get-Content $f.FullName -Raw; $au = "$($x.WLANProfile.MSM.security.authEncryption.authentication)"; [pscustomobject]@{ Network = $x.WLANProfile.name; Security = $au; Enterprise = ($au -match '^(WPA|WPA2|WPA3|WPA3ENT|WPA3ENT192)$') } } catch {}
        }
        Add-Appendix 'Saved Wi-Fi networks' $wl
        $ent = @($wl | Where-Object { $_.Enterprise })
        if ($ent.Count) { Add-R 'Company lock' 'Company (enterprise) Wi-Fi profiles' WARN (Join-Lines ($ent | ForEach-Object { $_.Network })) 'Enterprise Wi-Fi (802.1X) is used by companies/universities - suggests a company/school device.' }
        if (@($wl).Count) { Add-R $cat 'Saved Wi-Fi networks' INFO "$(@($wl).Count) saved Wi-Fi network(s) (names in appendix)." }
    } catch {} finally { Remove-Item $wtmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Invoke-Section 'Security settings' {
    $cat = 'Security'
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    $av = @(Get-Cim AntiVirusProduct 'root\SecurityCenter2' | ForEach-Object { $_.displayName })
    if ($av.Count) { Add-R $cat 'Antivirus products' INFO ($av -join ', ') }
    if ($mp) {
        $d = "Defender running mode: $($mp.AMRunningMode)`nReal-time protection: $($mp.RealTimeProtectionEnabled)`nTamper protection: $($mp.IsTamperProtected)`nVirus definitions: $($mp.AntivirusSignatureAge) day(s) old"
        if ($mp.AMRunningMode -eq 'Normal' -and -not $mp.RealTimeProtectionEnabled) { Add-R $cat 'Microsoft Defender' FAIL $d 'Real-time protection is OFF. Malware often disables it. Turn it on and run the scan.' }
        elseif ($mp.AntivirusSignatureAge -gt 14) { Add-R $cat 'Microsoft Defender' WARN $d 'Virus definitions are old - the PC has not been updating.' }
        else { Add-R $cat 'Microsoft Defender' PASS $d }
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $ex = @()
            foreach ($n in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') { foreach ($v in @($pref.$n)) { if ($v -and "$v" -notmatch 'N/A') { $ex += "$n : $v" } } }
            if ($ex.Count) {
                $bad = @($ex | Where-Object { $_ -match ':\s*([A-Za-z]:\\?$|.*\\(Users|AppData|Temp|ProgramData|Windows)\\?$|\.?exe$|\.?dll$|\*)' })
                Add-R $cat 'Defender exclusions' $(if ($bad.Count) { 'FAIL' } else { 'WARN' }) (Join-Lines $ex) 'Folders/files excluded from virus scanning. Malware and cracks add exclusions to hide. Ask why - a reset removes them.'
            } elseif ($script:IsAdmin) { Add-R $cat 'Defender exclusions' PASS 'No scan exclusions.' }
        } catch {}
        try {
            $thr = @(Get-MpThreat -ErrorAction Stop)
            if ($thr.Count) {
                $act = @($thr | Where-Object { $_.IsActive })
                Add-R $cat 'Malware detected in the past' $(if ($act.Count) { 'FAIL' } else { 'WARN' }) (Join-Lines ($thr | ForEach-Object { "$($_.ThreatName)  (active now: $($_.IsActive), ran: $($_.DidThreatExecute))" })) 'Defender has found malware on this PC before. If any is still active or "ran", the PC needs a full reset.'
            } else { Add-R $cat 'Malware detected in the past' PASS 'Defender has no history of detected threats.' }
        } catch {}
    } else { Add-R $cat 'Microsoft Defender' INFO 'Defender status unavailable (another antivirus may be in charge).' }
    $dp = Get-RegProps 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $rtp = Get-RegProps 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    if ($dp.DisableAntiSpyware -eq 1 -or $dp.DisableAntiVirus -eq 1 -or $rtp.DisableRealtimeMonitoring -eq 1) { Add-R $cat 'Defender disabled by policy' FAIL 'A policy switches Microsoft Defender off.' 'Typical of malware, cracks or "debloat" tools.' }
    $sp = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ($sp.EnableLUA -eq 0) { Add-R $cat 'User Account Control (UAC)' FAIL 'UAC is completely disabled.' 'Every program runs with full admin rights. Typical of tweaked/cracked systems.' }
    elseif ($sp.ConsentPromptBehaviorAdmin -eq 0) { Add-R $cat 'User Account Control (UAC)' WARN 'UAC prompts are turned off for administrators.' 'Programs can gain admin rights silently.' }
    else { Add-R $cat 'User Account Control (UAC)' PASS 'UAC is on.' }
    $ss = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    if ($ss -eq 0) { Add-R $cat 'SmartScreen' WARN 'SmartScreen is disabled by policy.' }
    try { $fwp = @(Get-NetFirewallProfile -ErrorAction Stop); $off = @($fwp | Where-Object { -not $_.Enabled }); if ($off.Count) { Add-R $cat 'Firewall' WARN ('Firewall OFF for: ' + (($off | ForEach-Object { $_.Name }) -join ', ')) 'Turn the firewall on.' } else { Add-R $cat 'Firewall' PASS 'Firewall is on for all profiles.' } } catch {}
    $wu = $script:Services | Where-Object { $_.Name -eq 'wuauserv' } | Select-Object -First 1
    $wuPol = Get-RegProps 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if ($wu.StartMode -eq 'Disabled' -or $wuPol.NoAutoUpdate -eq 1) { Add-R $cat 'Windows Update' WARN "Windows Update is disabled (service: $($wu.StartMode), policy NoAutoUpdate: $($wuPol.NoAutoUpdate))." 'Updates were blocked - often to keep a crack working. Security risk.' }
    $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) { $days = [int]((Get-Date) - $hf.InstalledOn).TotalDays; Add-R $cat 'Last Windows update installed' $(if ($days -gt 90) { 'WARN' } else { 'PASS' }) "$($hf.HotFixID) on $($hf.InstalledOn.ToString('yyyy-MM-dd')) ($days days ago)" $(if ($days -gt 90) { 'Not updated for months. Run Windows Update after buying.' } else { '' }) }
    if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0 -and $os.Caption -notmatch 'Home') { Add-R $cat 'Remote Desktop' WARN 'Remote Desktop connections into this PC are allowed.' 'Turn off unless you need it.' }
    foreach ($svn in @(@('RemoteRegistry', 'Remote Registry'), @('WinRM', 'Windows Remote Management'), @('sshd', 'OpenSSH server'), @('TlntSvr', 'Telnet server'))) {
        $s = $script:Services | Where-Object { $_.Name -eq $svn[0] } | Select-Object -First 1
        if ($s -and $s.State -eq 'Running') { Add-R $cat "$($svn[1]) running" WARN "$($svn[1]) service is running." 'Allows remote access/administration. Not normal on a home PC.' }
    }
    try { if ((Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) { Add-R $cat 'SMBv1' WARN 'Old insecure SMBv1 file sharing is enabled.' } } catch {}
}

Invoke-Section 'Remote control, spyware, miners & cracks' {
    $cat = 'Suspicious software'
    $n = Report-SigCategory $cat @('Remote access') 'Remote-control software lets someone control this PC over the internet. Fine if YOU installed it - on a bought PC it should not be there. A reset removes it.'
    $n += Report-SigCategory $cat @('Spyware / keylogger') 'Spy software records keystrokes, screens and passwords. Do not use this PC for anything until it is fully reset.'
    $n += Report-SigCategory $cat @('Employee monitoring') 'Employee monitoring software - tracks activity. Means it was a company PC; must be removed (reset).'
    $n += Report-SigCategory $cat @('Parental control') 'Parental control / monitoring software. Should be removed (reset).'
    $n += Report-SigCategory $cat @('Malware / hacking tool') 'Hacking tool / remote-access trojan names found. Treat the PC as compromised.'
    $n += Report-SigCategory $cat @('Crypto miner') 'Crypto-mining software wears out the CPU/GPU and is often malware. The hardware may have been run hot 24/7.'
    $n += Report-SigCategory $cat @('Piracy / activator') 'Pirated software / activators: not genuine and a very common source of malware.'
    $n += Report-SigCategory $cat @('Adware / junk') 'Adware / junk software. Not dangerous by itself but a reset is recommended.'
    if ($n -eq 0) { Add-R $cat 'Known bad / risky software' PASS 'No remote-control tools, spyware, miners, cracks or adware recognised in programs, services, processes, tasks or folders.' }
    $noPub = @($script:Programs | Where-Object { -not $_.Publisher -and -not $_.Hidden })
    if ($noPub.Count) { Add-R $cat 'Programs without a publisher' INFO (Join-Lines ($noPub | ForEach-Object { "$($_.Name) $($_.Version)" }) 20) 'Not necessarily bad, but look up anything you do not recognise.' }
    $recent = @($script:Programs | Where-Object { $_.InstallDate -match '^\d{8}$' -and [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null) -gt (Get-Date).AddDays(-7) })
    if ($recent.Count) { Add-R $cat 'Recently installed programs (7 days)' INFO (Join-Lines ($recent | ForEach-Object { "$($_.Name) ($($_.InstallDate))" })) 'Programs the seller installed just before selling - check you know what they are.' }
    $hidden = @($script:Programs | Where-Object { $_.Hidden -and -not $_.Publisher })
    Add-Appendix 'Installed programs' ($script:Programs | Where-Object { -not $_.Hidden } | Select-Object Name, Publisher, Version, InstallDate, For, Location)
    if ($hidden.Count) { Add-Appendix 'Hidden programs without publisher' ($hidden | Select-Object Name, Version, InstallDate, Location) }
    $procRisk = @($script:Processes | Where-Object { $_.ExecutablePath -match '(?i)\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Windows\\Temp\\|\\\$Recycle|\\ProgramData\\[^\\]+\.exe$|\\AppData\\Roaming\\[^\\]+\.exe$' })
    foreach ($p in $procRisk) { $s = Get-Sig $p.ExecutablePath; Add-R $cat "Process running from odd folder: $($p.Name)" $(if ($s.Status -eq 'Valid') { 'INFO' } else { 'FAIL' }) "$($p.ExecutablePath)`nSignature: $($s.Status) $($s.Signer)`nCommand: $(Short $p.CommandLine 250)" 'Programs normally run from Program Files. Running from Temp/Public/Roaming root is a classic malware trait.' }
    $fake = @($script:Processes | Where-Object { $_.Name -match '^(svchost|lsass|csrss|winlogon|services|smss|explorer|wininit|spoolsv|taskhostw|dllhost|conhost|rundll32)\.exe$' -and $_.ExecutablePath -and ($_.ExecutablePath -replace '^\\\\\?\\|^\\\?\?\\', '') -notmatch ('^(?i)' + [regex]::Escape($env:SystemRoot) + '\\(System32|SysWOW64|explorer\.exe|WinSxS)') } | Sort-Object ExecutablePath -Unique)
    foreach ($p in $fake) { Add-R $cat "Fake system process: $($p.Name)" FAIL "$($p.ExecutablePath)" 'A program pretending to be a Windows system process from the wrong folder - typical malware.' }
}

Invoke-Section 'Start-up items & hidden auto-start tricks' {
    $cat = 'Startup & persistence'
    $entries = New-Object System.Collections.ArrayList
    function Add-AS([string]$Loc, [string]$Name, [string]$Cmd) {
        $p = Get-ExePath $Cmd; $s = Get-Sig $p
        [void]$entries.Add([pscustomobject]@{ Where = $Loc; Name = $Name; Command = (Short $Cmd 300); File = $p; Signature = $s.Status; Signer = $s.Signer; MS = $s.IsMicrosoft })
    }
    $runPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    foreach ($h in $script:UserHives) { foreach ($s in 'Run', 'RunOnce', 'Policies\Explorer\Run') { $runPaths += "Registry::HKEY_USERS\$h\Software\Microsoft\Windows\CurrentVersion\$s" } }
    foreach ($rp in $runPaths) {
        $props = Get-RegProps $rp
        $loc = $rp
        if ($rp -match '^Registry::HKEY_USERS\\([^\\]+)\\(.*)$') { $loc = 'User ' + (Get-HiveUser $Matches[1]) + ': HKCU\' + $Matches[2] }
        if ($props) { foreach ($pp in $props.PSObject.Properties) { if ($pp.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { Add-AS $loc $pp.Name ([string]$pp.Value) } } }
    }
    $sh = $null; try { $sh = New-Object -ComObject WScript.Shell } catch {}
    $sDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($p in $script:Profiles) { $sDirs += (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    foreach ($sd in $sDirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $sd -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $cmd = $f.FullName
            if ($f.Extension -eq '.lnk' -and $sh) { try { $lk = $sh.CreateShortcut($f.FullName); $cmd = ('"' + $lk.TargetPath + '" ' + $lk.Arguments).Trim() } catch {} }
            Add-AS "Startup folder ($sd)" $f.Name $cmd
        }
    }
    $flag = @()
    foreach ($e in $entries) {
        if ($e.Command -match $script:CmdBadRx) { $flag += [pscustomobject]@{ S = 'FAIL'; T = "$($e.Name): $($e.Command)"; W = $e.Where } }
        elseif ($e.File -match $script:RiskyDirRx -or $e.Command -match $script:CmdOddRx) { $flag += [pscustomobject]@{ S = $(if ($e.Signature -eq 'Valid') { 'WARN' } else { 'FAIL' }); T = "$($e.Name): $($e.Command) [signature: $($e.Signature)]"; W = $e.Where } }
        elseif ($e.Signature -ne 'Valid' -and $e.Signature -ne 'Missing') { $flag += [pscustomobject]@{ S = 'WARN'; T = "$($e.Name): $($e.File) [signature: $($e.Signature)]"; W = $e.Where } }
    }
    foreach ($f in $flag) { Add-R $cat 'Suspicious start-up entry' $f.S "$($f.T)`nLocation: $($f.W)" 'Unsigned programs, scripts or hidden PowerShell starting with Windows. Look it up; if unknown, the PC needs a reset.' }
    if (-not $flag.Count) { Add-R $cat 'Start-up programs' PASS "$($entries.Count) start-up entries; all signed and from normal locations (list in appendix)." }
    Add-Appendix 'Start-up programs (Run keys & Startup folders)' ($entries | Select-Object Where, Name, Command, Signature, Signer)

    # Winlogon / AppInit / IFEO / accessibility backdoors
    $wl = Get-RegProps 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = "$($wl.Shell)".Trim()
    if ($shell -and $shell -notmatch '^(?i)(explorer\.exe|C:\\Windows\\explorer\.exe)$') { Add-R $cat 'Windows shell hijack' FAIL "Winlogon Shell = $shell" 'Something replaced or added to the Windows desktop shell. Classic malware/kiosk trick.' }
    $ui = "$($wl.Userinit)".Trim().TrimEnd(',').Trim()
    if ($ui -and $ui -notmatch '^(?i)(C:\\Windows\\system32\\userinit\.exe|userinit\.exe|%SystemRoot%\\system32\\userinit\.exe)$') { Add-R $cat 'Userinit hijack' FAIL "Winlogon Userinit = $ui" 'An extra program is launched at every sign-in via Userinit - malware trick.' }
    foreach ($h in $script:UserHives) { $us = Get-Reg "Registry::HKEY_USERS\$h\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'; if ($us) { Add-R $cat 'Per-user shell override' FAIL "User $(Get-HiveUser $h): Shell = $us" 'Replaces the desktop for this user.' } }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') { $p = Get-RegProps $k; if ("$($p.AppInit_DLLs)".Trim() -and $p.LoadAppInit_DLLs -eq 1) { Add-R $cat 'AppInit DLL injection' FAIL "AppInit_DLLs = $($p.AppInit_DLLs)" 'A DLL is injected into every program - used by malware and adware.' } }
    $acc = 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe'
    $ifeo = @()
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue)) {
        $dbg = Get-Reg $k.PSPath 'Debugger'
        if ($dbg) { $ifeo += [pscustomobject]@{ Exe = $k.PSChildName; Debugger = $dbg } }
    }
    foreach ($i in $ifeo) {
        if ($acc -contains $i.Exe.ToLower()) { Add-R $cat 'Login-screen backdoor' FAIL "$($i.Exe) is redirected to: $($i.Debugger)" 'Lets anyone open an admin command prompt at the login screen. Deliberate backdoor.' }
        elseif ($i.Debugger -notmatch '(?i)vsjitdebugger|windbg|devenv') { Add-R $cat 'Program hijack (IFEO debugger)' WARN "$($i.Exe) -> $($i.Debugger)" 'Starting this program secretly starts another one instead. Used by malware - and occasionally to block apps.' }
    }
    foreach ($a in $acc) {
        $f = Join-Path "$env:SystemRoot\System32" $a
        if (Test-Path -LiteralPath $f) {
            $vi = (Get-Item -LiteralPath $f).VersionInfo
            if ("$($vi.OriginalFilename)" -match '^(?i)(cmd|powershell|pwsh|explorer|taskmgr|regedit)\.exe') { Add-R $cat 'Login-screen backdoor' FAIL "$f is actually $($vi.OriginalFilename)" 'An accessibility tool was replaced with a command shell - deliberate backdoor.' }
        }
    }
    # LSA packages
    $lsa = Get-RegProps 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $known = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'livessp', 'negoexts', 'scecli', 'rassfm', '""', '')
    $odd = @()
    foreach ($n in 'Security Packages', 'Authentication Packages', 'Notification Packages') { foreach ($v in @($lsa.$n)) { if ($known -notcontains "$v".ToLower().Trim()) { $odd += "$n : $v" } } }
    if ($odd.Count) { Add-R $cat 'Unusual login (LSA) packages' WARN (Join-Lines $odd) 'Extra DLLs loaded into the Windows login process can capture passwords. Some security/VPN products add these - look them up.' }
    # WMI persistence
    $filters = @(Get-Cim __EventFilter 'root\subscription'); $consumers = @(Get-Cim __EventConsumer 'root\subscription')
    $badC = @($consumers | Where-Object { $_.CimClass.CimClassName -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer') -and $_.Name -notmatch '^(SCM Event Log Consumer|BVTConsumer)$' })
    $oddF = @($filters | Where-Object { $_.Name -notmatch '^(SCM Event Log Filter|BVTFilter)$' })
    if ($badC.Count) { Add-R $cat 'Hidden WMI auto-start' FAIL (Join-Lines ($badC | ForEach-Object { "$($_.Name): $($_.CommandLineTemplate)$($_.ScriptText)" })) 'Code that runs automatically via WMI event subscriptions - a well-known file-less malware technique.' }
    elseif ($oddF.Count) { Add-R $cat 'WMI event filters' WARN (Join-Lines ($oddF | ForEach-Object { "$($_.Name): $($_.Query)" })) 'Unusual WMI event filters exist. Some vendor tools use them; look them up.' }
    else { Add-R $cat 'Hidden WMI auto-start' PASS 'No WMI persistence found.' }

    # Scheduled tasks
    $tRows = @(); $tFlags = @()
    foreach ($t in $script:Tasks) {
        if (-not $t.Execute) { continue }
        $cmd = "$($t.Execute) $($t.Arguments)"
        $p = Get-ExePath $t.Execute
        $isMsPath = $t.Path -like '\Microsoft\*'
        $s = $null
        if (-not $isMsPath -or $p -notmatch ('^(?i)' + [regex]::Escape($env:SystemRoot))) { $s = Get-Sig $p }
        if ($cmd -match $script:CmdBadRx) { $tFlags += [pscustomobject]@{ S = 'FAIL'; T = "$($t.Path)`n$(Short $cmd 300)" } }
        elseif ($p -match $script:RiskyDirRx -or ($cmd -match $script:CmdOddRx -and $s -and $s.Status -ne 'Valid')) { $tFlags += [pscustomobject]@{ S = $(if ($s -and $s.Status -eq 'Valid') { 'WARN' } else { 'FAIL' }); T = "$($t.Path)`n$(Short $cmd 300)`nSignature: $(if ($s) { $s.Status })" } }
        elseif ($s -and $s.Exists -and $s.Status -ne 'Valid' -and $p -match '\.(exe|dll|com|scr)$') { $tFlags += [pscustomobject]@{ S = 'WARN'; T = "$($t.Path)`n$(Short $cmd 300)`nSignature: $($s.Status)" } }
        if (-not $isMsPath) { $tRows += [pscustomobject]@{ Task = $t.Path; State = $t.State; Runs = (Short $cmd 200); Signature = $(if ($s) { $s.Status }); Signer = $(if ($s) { $s.Signer }) } }
    }
    foreach ($f in $tFlags) { Add-R $cat 'Suspicious scheduled task' $f.S $f.T 'Scheduled tasks are a favourite way for malware to restart itself. Look it up; if unknown, reset the PC.' }
    if (-not $tFlags.Count) { Add-R $cat 'Scheduled tasks' PASS "$(@($script:Tasks).Count) task actions checked; nothing suspicious. Non-Microsoft tasks are listed in the appendix." }
    Add-Appendix 'Non-Microsoft scheduled tasks' $tRows

    # Services
    $sFlags = @(); $sRows = @()
    foreach ($s in $script:Services) {
        if (-not $s.PathName) { continue }
        $p = Get-ExePath $s.PathName
        if ($p -match '(?i)\\svchost\.exe$') {
            $dll = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" 'ServiceDll'
            if ($dll) { $p = Get-ExePath $dll } else { continue }
        }
        $sig = Get-Sig $p
        $thirdParty = -not $sig.IsMicrosoft
        if ($s.PathName -match $script:CmdBadRx) { $sFlags += [pscustomobject]@{ S = 'FAIL'; T = "$($s.DisplayName) [$($s.Name)]`n$(Short $s.PathName 300)" } }
        elseif ($p -match $script:RiskyDirRx -or $p -match '(?i)\\AppData\\') { $sFlags += [pscustomobject]@{ S = $(if ($sig.Status -eq 'Valid') { 'WARN' } else { 'FAIL' }); T = "$($s.DisplayName) [$($s.Name)] - $($s.State)`n$p`nSignature: $($sig.Status) $($sig.Signer)" } }
        elseif ($sig.Exists -and $sig.Status -ne 'Valid') { $sFlags += [pscustomobject]@{ S = 'WARN'; T = "$($s.DisplayName) [$($s.Name)] - $($s.State)`n$p`nSignature: $($sig.Status)" } }
        if ($thirdParty) { $sRows += [pscustomobject]@{ Service = $s.DisplayName; Name = $s.Name; State = $s.State; Start = $s.StartMode; File = $p; Signature = $sig.Status; Signer = $sig.Signer } }
    }
    foreach ($f in $sFlags) { Add-R $cat 'Suspicious service' $f.S $f.T 'Background services that are unsigned or live in user folders are a malware warning sign. Look it up.' }
    if (-not $sFlags.Count) { Add-R $cat 'Services' PASS "$(@($script:Services).Count) services checked; all signed and in normal locations." }
    Add-Appendix 'Non-Microsoft services' $sRows

    # Kernel drivers
    $dFlags = @()
    foreach ($d in @(Get-Cim Win32_SystemDriver | Where-Object { $_.State -eq 'Running' })) {
        $p = Get-ExePath $d.PathName
        $sig = Get-Sig $p
        if (-not $sig.Exists) { continue }
        if ($sig.Status -ne 'Valid') { $dFlags += "$($d.DisplayName) [$($d.Name)] $p - signature: $($sig.Status)" }
        elseif ($p -match $script:RiskyDirRx -or $p -match '(?i)\\AppData\\|\\ProgramData\\|\\Users\\|\\Temp\\') { $dFlags += "$($d.DisplayName) [$($d.Name)] $p - unusual location (signed by $($sig.Signer))" }
    }
    if ($dFlags.Count) { Add-R $cat 'Unusual kernel drivers' WARN (Join-Lines $dFlags) 'Drivers run with full system power. Unsigned/odd drivers can be rootkits, game cheats or old hardware tools. Look them up.' }
    else { Add-R $cat 'Kernel drivers' PASS 'All running drivers are signed and in normal locations.' }

    # Browser policies (forced extensions / hijacked home page)
    $bp = @()
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox') {
        if (Test-Path $k) {
            $p = Get-RegProps $k
            foreach ($n in 'HomepageLocation', 'DefaultSearchProviderSearchURL', 'RestoreOnStartupURLs', 'NewTabPageLocation') { if ($p.$n) { $bp += "$k : $n = $($p.$n)" } }
            $fl = Get-RegProps "$k\ExtensionInstallForcelist"
            if ($fl) { foreach ($pp in $fl.PSObject.Properties) { if ($pp.Name -notmatch '^PS') { $bp += "$k : forced extension $($pp.Value)" } } }
        }
    }
    if ($bp.Count) { Add-R $cat 'Browser forced settings' WARN (Join-Lines $bp) 'Browser extensions/home pages forced by policy - either company management or adware/browser hijacker.' }
}

Invoke-Section 'Network tampering' {
    $cat = 'Network'
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hl = @(Get-Content $hostsFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' })
    if ($hl.Count) {
        $pir = @($hl | Where-Object { $_ -match '(?i)microsoft|windowsupdate|activation|licens|adobe|autodesk|kms|office' })
        Add-R $cat 'Hosts file entries' $(if ($pir.Count) { 'FAIL' } else { 'WARN' }) (Join-Lines $hl) $(if ($pir.Count) { 'Activation/licence servers are blocked - classic sign of pirated software.' } else { 'The hosts file redirects websites. Can be ad-blocking - or malware sending you to fake sites (e.g. banks).' })
    } else { Add-R $cat 'Hosts file' PASS 'Hosts file is clean.' }
    $px = @()
    foreach ($h in $script:UserHives) {
        $p = Get-RegProps "Registry::HKEY_USERS\$h\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if ($p.ProxyEnable -eq 1 -and $p.ProxyServer) { $px += "User $(Get-HiveUser $h): proxy $($p.ProxyServer)" }
        if ($p.AutoConfigURL) { $px += "User $(Get-HiveUser $h): auto-config script $($p.AutoConfigURL)" }
    }
    $wh = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings'
    if ($wh -is [byte[]] -and $wh.Length -ge 16) { try { if (([BitConverter]::ToInt32($wh, 8) -band 2) -and [BitConverter]::ToInt32($wh, 12) -gt 0) { $px += 'System (WinHTTP) proxy: ' + [Text.Encoding]::ASCII.GetString($wh, 16, [BitConverter]::ToInt32($wh, 12)) } } catch {} }
    if ($px.Count) { Add-R $cat 'Proxy settings' WARN (Join-Lines $px) 'Internet traffic is routed through a proxy - used by companies, and by malware to spy on traffic.' }
    else { Add-R $cat 'Proxy settings' PASS 'No proxy configured.' }
    $priv = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fe80|fec0|::1)'
    $pub = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3', '76.76.2.0', '76.76.10.0', '185.228.168.9', '185.228.169.9')
    $dns = @()
    try {
        $up = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
        foreach ($d in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $up -contains $_.InterfaceIndex })) { foreach ($a in @($d.ServerAddresses)) { if ($a -notmatch $priv -and $pub -notcontains $a) { $dns += "$($d.InterfaceAlias): $a" } } }
    } catch {}
    if ($dns.Count) { Add-R $cat 'DNS servers' INFO (Join-Lines $dns) 'Unusual DNS server. Can be your internet provider (normal) - or a DNS hijack redirecting websites. Compare with your own network once home.' }
    else { Add-R $cat 'DNS servers' PASS 'DNS uses the local router or a well-known public resolver.' }
    $roots = @(); try { $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop) + @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue) } catch {}
    $fatalRx = 'Superfish|eDellRoot|DSDTestProvider|Komodia|PrivDog'
    $corpRx = 'Zscaler|Netskope|Forcepoint|Websense|Blue ?Coat|Fortinet|FortiGate|Palo Alto|Cisco Umbrella|OpenDNS|Barracuda|WatchGuard|Lightspeed|Securly|GoGuardian|iboss|ContentKeeper|Smoothwall|Menlo Security|Cloudflare.*Gateway|Sophos SSL|Untangle'
    $devRx = 'DO_NOT_TRUST|Fiddler|Charles Proxy|mitmproxy|PortSwigger|Burp'
    foreach ($c in $roots) {
        if ($c.Subject -match $fatalRx) { Add-R $cat 'Dangerous root certificate' FAIL $c.Subject 'A known-malicious traffic-interception certificate. Remove / reset.' }
        elseif ($c.Subject -match $corpRx) { Add-R 'Company lock' 'Company traffic-inspection certificate' WARN $c.Subject 'Used by company firewalls to inspect encrypted web traffic - this was a company device.' }
        elseif ($c.Subject -match $devRx) { Add-R $cat 'Traffic interception certificate' WARN $c.Subject 'A debugging/interception proxy can read your HTTPS traffic. Remove it (or reset).' }
    }
    $procs = @{}; foreach ($p in $script:Processes) { $procs[[int]$p.ProcessId] = $p.Name }
    $listen = @()
    try { $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } | Select-Object LocalAddress, LocalPort, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } }, OwningProcess | Sort-Object LocalPort -Unique) } catch {}
    Add-Appendix 'Network ports open to other computers' $listen
    $rport = @{ 3389 = 'Remote Desktop'; 5900 = 'VNC'; 5901 = 'VNC'; 5938 = 'TeamViewer'; 7070 = 'AnyDesk'; 6568 = 'AnyDesk'; 4899 = 'Radmin'; 21115 = 'RustDesk'; 21116 = 'RustDesk'; 21118 = 'RustDesk'; 8040 = 'ScreenConnect'; 5650 = 'Remcos (RAT)'; 1337 = 'common backdoor port'; 31337 = 'common backdoor port'; 4444 = 'Metasploit default'; 23 = 'Telnet'; 22 = 'SSH' }
    $hitp = @($listen | Where-Object { $rport.ContainsKey([int]$_.LocalPort) } | ForEach-Object { "Port $($_.LocalPort) ($($rport[[int]$_.LocalPort])) - process $($_.Process)" })
    if ($hitp.Count) { Add-R $cat 'Remote-access ports open' WARN (Join-Lines $hitp) 'Something is waiting for incoming remote connections.' }
    $odd = @($listen | Where-Object { $_.Process -and $_.Process -notmatch '^(System|svchost|lsass|wininit|services|spoolsv|Idle|msedge|MsMpEng|NisSrv|jhi_service|mDNSResponder|Spotify|steam)$' } | ForEach-Object { "$($_.LocalPort): $($_.Process)" })
    if ($odd.Count) { Add-R $cat 'Programs accepting network connections' INFO (Join-Lines $odd) 'Look up anything you do not recognise.' }
}

Invoke-Section 'Original parts check (swapped / aftermarket parts)' {
    $cat = 'Parts'
    # --- RAM ---
    $jedec = @{ '80CE' = 'Samsung'; 'CE00' = 'Samsung'; '802C' = 'Micron'; '2C00' = 'Micron'; '80AD' = 'SK hynix'; 'AD00' = 'SK hynix'; '859B' = 'Crucial'; '9B05' = 'Crucial'; '0198' = 'Kingston'; '9801' = 'Kingston'; '04CB' = 'ADATA'; 'CB04' = 'ADATA'; '029E' = 'Corsair'; '9E02' = 'Corsair'; '04CD' = 'G.Skill'; 'CD04' = 'G.Skill'; '0443' = 'Ramaxel'; '4304' = 'Ramaxel'; '830B' = 'Nanya'; '0B83' = 'Nanya'; '04EF' = 'TeamGroup'; 'EF04' = 'TeamGroup'; '8502' = 'Patriot' }
    $mods = @($script:RamMods)
    $rows = foreach ($m in $mods) {
        $mk = "$($m.Manufacturer)".Trim(); if ($jedec.ContainsKey($mk.ToUpper())) { $mk = $jedec[$mk.ToUpper()] }
        [pscustomobject]@{ Slot = $m.DeviceLocator; Maker = $mk; Part = "$($m.PartNumber)".Trim(); GB = [math]::Round($m.Capacity / 1GB); MHz = $(if ($m.ConfiguredClockSpeed) { $m.ConfiguredClockSpeed } else { $m.Speed }) }
    }
    $rows = @($rows)
    if ($rows.Count -gt 1) {
        $makers = @($rows | ForEach-Object { $_.Maker } | Where-Object { $_ -and $_ -notmatch '^(Unknown|Undefined|0+)$' } | Select-Object -Unique)
        $parts = @($rows | ForEach-Object { $_.Part } | Where-Object { $_ } | Select-Object -Unique)
        $sizes = @($rows | ForEach-Object { $_.GB } | Select-Object -Unique)
        $d = ($rows | ForEach-Object { "$($_.Slot): $($_.GB) GB $($_.Maker) $($_.Part) $($_.MHz) MHz" }) -join "`n"
        if ($makers.Count -gt 1 -or $parts.Count -gt 1) { Add-R $cat 'Memory modules match' WARN $d 'The memory sticks are from different makers/models, so at least one was added or replaced after the laptop left the factory. Usually fine, but mismatched sticks can run slower and are a known cause of random crashes. Mention it if selling; ask about it if buying.' }
        elseif ($sizes.Count -gt 1) { Add-R $cat 'Memory modules match' INFO $d 'Different sizes: part of the memory runs in slower single-channel mode.' }
        else { Add-R $cat 'Memory modules match' PASS "Matching memory modules (as from the factory):`n$d" }
    } elseif ($rows.Count -eq 1) { Add-R $cat 'Memory modules' INFO ("One memory module: " + "$($rows[0].GB) GB $($rows[0].Maker) $($rows[0].Part)") }
    $retailRam = @($rows | Where-Object { "$($_.Maker) $($_.Part)" -match '(?i)Crucial|Corsair|G\.?Skill|TeamGroup|Team Group|Patriot|HyperX|Lexar|^KF\d|\bKF\d|\bHX\d|Kingston Fury|CT\d+G\d|CMS[OX]|F4-\d|F5-\d|TED\d' })
    if ($retailRam.Count) { Add-R $cat 'Upgraded memory' INFO (Join-Lines ($retailRam | ForEach-Object { "$($_.Slot): $($_.Maker) $($_.Part)" })) 'This is a shop-bought (retail) memory stick, not a factory part - the RAM has been upgraded or replaced. Fine if it tests OK; say "RAM upgraded" in a listing.' }
    if ($script:Spec['RAM'] -match 'LPDDR') { Add-R $cat 'Soldered memory' INFO 'LPDDR memory is soldered to the motherboard.' 'It cannot be upgraded or swapped - what you see is what you get.' }

    # --- battery ---
    $packMakers = '(?i)SMP|Simplo|SANYO|Panasonic|LGC|\bLG\b|LG Chem|LGES|SDI|Samsung|SONY|Murata|BYD|Celxpert|CPT|DYNAPACK|\bDP\b|SUNWODA|SWD|COSMX|\bATL\b|Amperex|Hitachi|Maxell|HPM|DESAY|\bASP\b|Hewlett|\bHP\b|HPQ|Dell|Lenovo|ASUS|ASUSTeK|Acer|Microsoft|Apple|Toshiba|Dynabook|Razer|MSI|Huawei|Honor|Xiaomi|Fujitsu|Getac|Framework|Coslight|Lishen|EVE|Greatpower|Highpower|SCUD|Gotion|NVT|Tianjin|Shenzhen'
    foreach ($b in @($script:BatList)) {
        $who = "$($b.Maker)".Trim()
        $d = "Battery maker: '$who'   ID: '$($b.Id)'   Made: '$($b.MadeOn)'   Design capacity: {0:N0} mWh   Cycles: {1}" -f $b.Design, $b.Cycles
        if (-not $who -or $who -match '^(Unknown|Default|OEM|Generic|None|0+|\s*|Not Specified|To be filled.*)$') { Add-R $cat 'Battery is original' WARN $d 'The battery does not report a real maker - typical of cheap aftermarket replacement batteries (less capacity, faster wear, higher swelling risk).' }
        elseif ($who -notmatch $packMakers) { Add-R $cat 'Battery is original' WARN $d "'$who' is not a known laptop-battery supplier, so this may be an aftermarket replacement. Check the battery label (open the bottom cover or the maker's parts list) if it matters." }
        elseif ($b.Cycles -eq 0 -and $b.Design -gt 0 -and ($b.Full / $b.Design) -lt 0.85) { Add-R $cat 'Battery is original' WARN $d 'Cycle counter shows 0 although the battery is worn - aftermarket batteries often do not report cycles.' }
        else { Add-R $cat 'Battery is original' PASS "$d`nMaker is a known laptop battery supplier." }
    }

    # --- storage ---
    $cheap = '(?i)KingSpec|Fanxiang|Netac|Goldenfir|Walram|ShiJi|KingFast|Reletech|Vaseky|Kingdian|BiwinTech|Ediloca|Eaget|Zheino|Teclast|Hikvision|\bXray\b|Generic|^SSD\s*\d+\s*G|^NVMe SSD\s*\d|^\d+GB SSD|INDMEM|Somnambulist|ORICO'
    $retail = '(?i)\b(8[4-9]0|9[4-9]0|870|980|990)\s*(EVO|PRO|QVO)|Crucial\s*(P\d|MX|BX|T\d)|\bCT\d{3,4}(P\d|MX|BX)|WD(S|C)?\s*(Blue|Black|Green)|WDS\d|SN5[78]0|SN7[57]0|SN8[05]0|SN850X|Kingston\s*(NV|A2000|KC|SNV|A400|SA400|SKC|Fury)|\bSNV\d|\bSA400|Lexar|Team\s*Group|T-FORCE|ADATA\s*(SU|XPG|Legend)|XPG|Patriot|Sabrent|Silicon Power|\bSP\d{3}GB|Corsair\s*MP|Seagate\s*(BarraCuda|FireCuda)|SanDisk\s*(Ultra|Extreme)|Intel\s*SSD\s*6[67]0p|PNY|Transcend|Inland|Micro Center|HP\s*SSD\s*(EX|FX)'
    foreach ($m in @($script:DriveModels)) {
        if ($m -match $cheap) { Add-R $cat 'Drive is original' WARN "Drive: $m" 'This looks like a cheap no-name drive, so the original was almost certainly replaced. These often have poor endurance and slow speeds. Check the drive health and speed results; buyers may treat it as a downgrade.' }
        elseif ($m -match $retail) { Add-R $cat 'Drive is original' INFO "Drive: $m" 'This is a shop-bought (retail) drive, not a factory part - the storage was upgraded or replaced. Fine if healthy; say "SSD upgraded" in a listing.' }
        else { Add-R $cat 'Drive is original' PASS "Drive: $m - looks like a factory (OEM) part." }
    }

    # --- motherboard ---
    $bbs = "$($bb.SerialNumber)".Trim()
    if ($script:Brand -ne 'Other' -and $script:Brand -ne 'Virtual' -and $script:IsLaptop -and $bbs -match '^(|0+|Default string|To be filled.*|None|N/A|Base Board Serial Number|\s+)$') { Add-R $cat 'Motherboard' WARN "Motherboard serial is blank/generic: '$bbs'" 'On a brand laptop this usually means the motherboard was replaced (repair or a generic board).' }
    elseif ($script:Brand -eq 'Dell' -and $script:Serial -and $bbs -and $bbs -notmatch [regex]::Escape($script:Serial)) { Add-R $cat 'Motherboard' INFO "Motherboard serial '$bbs' does not contain the service tag '$($script:Serial)'." 'On Dell laptops this can mean the motherboard was replaced (e.g. a warranty repair). Not necessarily bad - ask about repair history.' }

    # --- where to see the true factory parts ---
    $look = switch ($script:Brand) {
        'Dell' { "Dell lists the ORIGINAL parts for this exact laptop: https://www.dell.com/support/home/en-us/product-support/servicetag/$([uri]::EscapeDataString($script:Serial))/overview > 'View product specs'." }
        'HP' { "HP PartSurfer lists the original parts for this serial: https://partsurfer.hp.com (enter $($script:Serial))." }
        'Lenovo' { "Lenovo PSREF lists the factory options for this model: https://psref.lenovo.com (search '$($csp.Version)' / type $($script:Model)). The serial lookup on pcsupport.lenovo.com shows the original parts list." }
        default { "Compare with the maker's specification sheet for $($script:Manufacturer) $($script:FriendlyModel)." }
    }
    Add-R $cat 'Factory parts list' MANUAL $look 'Compare the memory, drive and battery found above with the original parts.'
}

Invoke-Section 'Encryption, power plan & Windows 11 readiness' {
    $cat = 'Security'
    $bl = $null; try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch {}
    if ($bl) {
        $prot = (@($bl.KeyProtector) | ForEach-Object { "$($_.KeyProtectorType)" }) -join ', '
        $d = "Drive $($env:SystemDrive): $($bl.VolumeStatus), protection $($bl.ProtectionStatus), $($bl.EncryptionPercentage)% encrypted`nKey protectors: $prot"
        if ("$($bl.ProtectionStatus)" -eq 'On') {
            if ($script:Own) { Add-R $cat 'BitLocker / device encryption' PASS $d 'Make sure YOU have the recovery key: Settings > Privacy & security > Device encryption, or account.microsoft.com/devices/recoverykey. If the key belongs to the previous owner, turn encryption off and on again (or reset the PC) so a new key is made for your account.' }
            else { Add-R $cat 'BitLocker / device encryption' INFO $d 'Fine if you will reset the PC. If you keep it as-is, the recovery key belongs to the seller (or their company) - after a BIOS change you could be locked out.' }
        } elseif ("$($bl.VolumeStatus)" -match 'Progress') { Add-R $cat 'BitLocker / device encryption' INFO $d }
        else { Add-R $cat 'BitLocker / device encryption' $(if ($script:Own) { 'WARN' } else { 'INFO' }) $d $(if ($script:Own) { 'The drive is not encrypted. If the laptop is stolen, your files can be read. Turn on Device encryption / BitLocker (key saved to your Microsoft account).' } else { '' }) }
    } else {
        try {
            $sh = New-Object -ComObject Shell.Application
            $v = $sh.NameSpace(17).ParseName($env:SystemDrive).ExtendedProperty('System.Volume.BitLockerProtection')
            $txt = @{ 1 = 'ON'; 2 = 'OFF'; 3 = 'encrypting'; 4 = 'decrypting'; 5 = 'suspended'; 6 = 'ON (locked)' }[[int]$v]
            if ($txt) { Add-R $cat 'BitLocker / device encryption' INFO "Encryption of $($env:SystemDrive): $txt (details need admin rights)." }
        } catch {}
    }
    $plan = (& powercfg.exe /getactivescheme 2>&1 | Out-String).Trim()
    if ($plan -match '\((.+)\)') { $plan = $Matches[1] }
    Add-R 'Performance' 'Power plan' INFO "Active power plan: $plan" 'For the most accurate performance tests use Balanced or High performance while plugged in.'
    if ([int]$os.BuildNumber -lt 22000) {
        $cpu = "$($script:CpuName)"
        $tpmOk = $false; try { $t = Get-Cim Win32_Tpm 'root\cimv2\security\microsofttpm' | Select-Object -First 1; $tpmOk = ("$($t.SpecVersion)" -match '^2') } catch {}
        $gen = ''; if ($cpu -match 'i[3579]-(\d{4,5})') { $n = $Matches[1]; if ($n.Length -eq 5) { $gen = [int]$n.Substring(0, 2) } else { $gen = [int]$n.Substring(0, 1) } }
        $cpuOk = ($cpu -match 'Ryzen [3579] ([3-9]\d{3}|\d{4}[A-Z])|Ryzen AI|Core Ultra|Snapdragon') -or ($gen -ne '' -and $gen -ge 8)
        $d = "TPM 2.0: $tpmOk   Supported CPU (rough check): $cpuOk   ($cpu)"
        if ($tpmOk -and $cpuOk) { Add-R 'Windows licence' 'Windows 11 upgrade' PASS $d 'Can be upgraded to Windows 11 for free (Settings > Windows Update).' }
        else { Add-R 'Windows licence' 'Windows 11 upgrade' WARN $d 'Probably cannot officially run Windows 11. Windows 10 no longer gets free security updates - factor this into the value.' }
    }
}

Invoke-Section 'Event-log security audit (last 30 days)' {
    $cat = 'Security'
    $since = (Get-Date).AddDays(-30)
    $clr = @(Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $since } 50)
    $clr += Get-Events @{ LogName = 'Security'; Id = 1102; StartTime = $since } 50
    if ($clr.Count) { Add-R $cat 'Event logs were cleared' WARN (Join-Lines ($clr | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm')) - $(Short $_.Message 120)" })) 'Someone wiped the Windows logs recently. Sellers sometimes do this to hide crashes or errors - or it is part of a clean-up. Ask why.' }
    else { Add-R $cat 'Event logs were cleared' PASS 'No log clearing in the last 30 days.' }
    $def = Get-Events @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1116, 1117, 5001, 5007, 5010, 5012); StartTime = $since } 300
    $det = @($def | Where-Object { $_.Id -in 1116, 1117 })
    $off = @($def | Where-Object { $_.Id -in 5001, 5010, 5012 })
    $excl = @($def | Where-Object { $_.Id -eq 5007 -and $_.Message -match 'Exclusions' })
    if ($det.Count) { Add-R $cat 'Defender detections (log)' WARN ("$($det.Count) detection/action event(s):`n" + (Join-Lines ($det | Select-Object -First 8 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd')) " + (Short (($_.Message -split "`n" | Where-Object { $_ -match 'Name:|Path:' }) -join ' ') 160) }))) 'Malware was found and handled recently. Check the Malware scan section result.' }
    if ($off.Count) { Add-R $cat 'Defender was switched off' WARN ("$($off.Count) time(s) protection was disabled. Last: $($off[0].TimeCreated)") 'Someone (or something) turned virus protection off recently.' }
    if ($excl.Count) { Add-R $cat 'Defender exclusions were changed' WARN (Join-Lines ($excl | Select-Object -First 5 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd')) " + (Short (($_.Message -split "`n" | Where-Object { $_ -match 'New value' }) -join ' ') 200) })) 'Folders were excluded from virus scanning - a common malware / crack trick.' }
    $ps = Get-Events @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since; Level = 3 } 300
    $dlExec = '(?is)(DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|\biwr\s|Invoke-RestMethod|Start-BitsTransfer).{0,400}(\bIEX\b|Invoke-Expression|Start-Process|\.Invoke\(|Reflection\.Assembly\]::Load)|(\bIEX\b|Invoke-Expression).{0,300}(DownloadString|FromBase64String|Net\.WebClient)'
    $bad = @($ps | Where-Object { $_.Message -match $dlExec -and "$($_.Properties[4].Value)" -ne $PSCommandPath -and $_.Message -notmatch 'LaptopCheck' })
    if ($bad.Count) { Add-R $cat 'Suspicious PowerShell activity' WARN ("$($bad.Count) suspicious script(s) logged, e.g.:`n" + (Short $bad[0].Message 400)) 'Encoded or download-and-run PowerShell commands were executed. Can be admin tools, but is also how malware installs itself.' }
    $svcCrash = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7031, 7034); StartTime = $since } 300
    $secCrash = @($svcCrash | Where-Object { $_.Message -match 'Defender|Security Center|Firewall|Windows Update|WinDefend|wscsvc|mpssvc' })
    if ($secCrash.Count) { Add-R $cat 'Security services crashing' WARN (Join-Lines ($secCrash | Select-Object -First 6 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd')) $(Short $_.Message 140)" })) 'Security services that keep crashing can be a sign of malware tampering.' }
}

Invoke-Section 'Internet & Wi-Fi speed' {
    $cat = 'Wireless'
    $wi = (& netsh.exe wlan show interfaces 2>&1 | Out-String)
    if ($wi -match '(\d{1,3})%') { $sig = [int]$Matches[1]; $rate = ''; if ($wi -match '(?m)^\s*\S.*\(Mbps\)\s*:\s*(\d+)') { $rate = " link speed ~$($Matches[1]) Mbps" }; Add-R $cat 'Wi-Fi signal' $(if ($sig -ge 50) { 'PASS' } else { 'INFO' }) "Signal: $sig%$rate" $(if ($sig -lt 50) { 'Weak signal - move closer to the router and re-test. If it stays weak next to the router, the antenna may be damaged/disconnected.' } else { '' }) }
    if (-not $script:Online) { Add-R $cat 'Internet speed' INFO 'Not connected to the internet - speed test skipped.' 'Connect to Wi-Fi (e.g. your phone hotspot) to test.'; return }
    try {
        $p = New-Object System.Net.NetworkInformation.Ping; $times = @()
        for ($i = 0; $i -lt 5; $i++) { $r = $p.Send('1.1.1.1', 2000); if ($r.Status -eq 'Success') { $times += $r.RoundtripTime } }
        $lat = if ($times.Count) { '{0:N0} ms' -f ($times | Measure-Object -Average).Average } else { 'no reply' }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $wc = New-Object System.Net.WebClient
        $bytes = $wc.DownloadData('https://speed.cloudflare.com/__down?bytes=25000000')
        $sw.Stop()
        $mbps = ($bytes.Length * 8 / 1e6) / $sw.Elapsed.TotalSeconds
        Add-R $cat 'Internet speed' INFO ("Download: {0:N0} Mbit/s (25 MB test)   Ping: {1}   Lost pings: {2}/5" -f $mbps, $lat, (5 - $times.Count)) 'Depends mostly on the network you are on. Compare with your phone on the same Wi-Fi - a much slower result on the laptop points to a weak Wi-Fi card/antenna.'
    } catch { Add-R $cat 'Internet speed' INFO ('Speed test failed: ' + $_.Exception.Message) }
}

Invoke-Section 'Every-file scan (names, locations, hidden & disguised files)' {
    $cat = 'Files'
    if ($SkipFileScan) { Add-R $cat 'File scan' INFO 'Skipped (-SkipFileScan).'; return }
    if (-not $script:HasNative) { Add-R $cat 'File scan' INFO 'Skipped - fast scanner could not load.'; return }
    $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID + '\' })
    $usbRoot = ([IO.Path]::GetPathRoot($PSCommandPath))
    $drives = @($drives | Where-Object { $_ -ne $usbRoot -or $_ -eq ($env:SystemDrive + '\') })
    $hits = New-Object System.Collections.ArrayList
    [LcWalker]::Total = 0; [LcWalker]::Dirs = 0; [LcWalker]::Denied = 0
    foreach ($d in $drives) {
        Write-Host "   scanning every file name on $d ..." -ForegroundColor DarkGray
        try { foreach ($h in [LcWalker]::Scan($d, $script:ExecExts, $script:BadFileNameRx, $script:RiskyDirRx, 5000)) { [void]$hits.Add($h) } } catch { Add-R $cat "Scan of $d" INFO $_.Exception.Message }
    }
    $scanned = [LcWalker]::Total
    Add-R $cat 'Files examined' INFO ("{0:N0} files in {1:N0} folders checked on {2} ({3:N0} folders could not be opened - normally protected system folders)." -f $scanned, [LcWalker]::Dirs, ($drives -join ' '), [LcWalker]::Denied) 'This checks every file NAME and LOCATION. To scan the CONTENT of every file for malware, choose the Defender Full scan.'
    $rows = @(); $temp = 0; $checked = 0
    foreach ($h in $hits) {
        $isTemp = $h.FilePath -match '(?i)\\(AppData\\Local\\Temp|Windows\\Temp)\\'
        $sev = 'WARN'
        $sig = $null
        if ($h.FilePath -match '(?i)^[A-Z]:\\(pagefile|hiberfil|swapfile|DumpStack\.log)') { continue }
        if ($h.Reason -like 'Name matches*' -and $h.FilePath -match '(?i)\.(exe|dll|sys)$') { $sig = Get-Sig $h.FilePath; if ($sig.Status -eq 'Valid' -and $sig.IsMicrosoft) { continue } }
        if ($h.Reason -like 'Program/script*' -or $h.Reason -like 'Hidden*') {
            if ($h.FilePath -match '(?i)\.(exe|dll|sys|scr|com|cpl|msi|ocx)$') {
                if ($checked -lt 600) { $sig = Get-Sig $h.FilePath; $checked++ }
                if ($sig -and $sig.Status -eq 'Valid') { continue }   # properly signed program - fine
            }
            if ($isTemp) { $temp++; $sev = 'INFO' }
        } else { $sev = 'FAIL' }
        $rows += [pscustomobject]@{ Severity = $sev; Reason = $h.Reason; File = $h.FilePath; Size = $h.Size; Modified = $h.Modified; Signature = $(if ($sig) { $sig.Status } else { '' }) }
    }
    Add-Appendix 'Flagged files' ($rows | Sort-Object @{ e = { @{ 'FAIL' = 0; 'WARN' = 1; 'INFO' = 2 }[$_.Severity] } }, File)
    $f = @($rows | Where-Object { $_.Severity -eq 'FAIL' })
    $w = @($rows | Where-Object { $_.Severity -eq 'WARN' })
    if ($f.Count) { Add-R $cat 'Disguised / known-bad files' FAIL (Join-Lines ($f | ForEach-Object { "$($_.Reason): $($_.File)" }) 20) 'Files named like malware/cracks or disguised with fake extensions. Do not open them. The PC needs a full reset.' }
    if ($w.Count) { Add-R $cat 'Unsigned programs/scripts in unusual places' WARN (Join-Lines ($w | ForEach-Object { "$($_.File)  [$($_.Signature)]" }) 20) 'Programs and scripts outside Program Files without a valid signature. Many are harmless leftovers - look up any you do not recognise.' }
    if ($temp) { Add-R $cat 'Programs in Temp folders' INFO "$temp unsigned program/script files in temporary folders (listed in appendix)." 'Usually installer leftovers - safe to clean with Disk Clean-up.' }
    if (-not $f.Count -and -not $w.Count) { Add-R $cat 'Suspicious files' PASS 'No disguised, known-bad, or unsigned programs in unusual locations.' }

    # top-level folders on each drive
    $knownTop = '^(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|PerfLogs|Recovery|\$Recycle\.Bin|\$WinREAgent|\$SysReset|\$Windows\.~BT|\$Windows\.~WS|\$GetCurrent|\$WINDOWS\.~Q|System Volume Information|Documents and Settings|Config\.Msi|MSOCache|Intel|AMD|NVIDIA|Drivers|DRIVERS|SWSetup|SWTOOLS|Dell|HP|Lenovo|OneDriveTemp|inetpub|ESD|XboxGames|Temp|tmp|OEM|Apps|Boot|EFI|Logs|found\.\d+|SupportAssist|Riot Games|Games|SteamLibrary|Microsoft|Realtek|AMD|Asus|MSI|Acer|Huawei)$'
    $oddTop = @()
    foreach ($d in $drives) { foreach ($x in @(Get-ChildItem -LiteralPath $d -Directory -Force -ErrorAction SilentlyContinue)) { if ($x.Name -notmatch $knownTop) { $oddTop += "$($x.FullName)  (created $($x.CreationTime.ToString('yyyy-MM-dd')))" } } }
    if ($oddTop.Count) { Add-R $cat 'Non-standard folders at drive root' INFO (Join-Lines $oddTop 30) 'Not a standard Windows folder. Usually user data or programs - take a look at anything you do not recognise.' }
    $rand = @()
    foreach ($fo in $script:Folders) {
        $n = $fo.Name
        if ($n -match '^[A-Za-z0-9]{6,}$' -and ([regex]::Matches($n, '[0-9]+|[A-Za-z]+')).Count -ge 6) { $rand += "$($fo.Full)  (created $($fo.Created.ToString('yyyy-MM-dd')))" }
    }
    if ($rand.Count) { Add-R $cat 'Random-looking folder names' WARN (Join-Lines $rand) 'Malware often uses random folder names in ProgramData / AppData. Check what is inside.' }
    $hidSys = @()
    foreach ($p in $script:Profiles) { foreach ($x in @(Get-ChildItem -LiteralPath $p.LocalPath -Force -Directory -ErrorAction SilentlyContinue | Where-Object { ($_.Attributes -band [IO.FileAttributes]::Hidden) -and ($_.Attributes -band [IO.FileAttributes]::System) -and $_.Name -notmatch '^(AppData|Application Data|Cookies|Local Settings|My Documents|NetHood|PrintHood|Recent|SendTo|Start Menu|Templates|IntelGraphicsProfiles|MicrosoftEdgeBackups)$' })) { $hidSys += $x.FullName } }
    if ($hidSys.Count) { Add-R $cat 'Super-hidden folders in user profiles' WARN (Join-Lines $hidSys) 'Folders marked hidden+system in a user profile are unusual - malware hides this way.' }
}

Invoke-Section 'Performance tests (disk speed, CPU load, RAM)' {
    $cat = 'Performance'
    if (-not $SkipDiskBench -and $script:IsAdmin) {
        Write-Host '   disk speed test (about 30 s)...' -ForegroundColor DarkGray
        $o1 = (& winsat.exe disk -seq -read -drive $env:SystemDrive.TrimEnd(':') 2>&1 | Out-String)
        $o2 = (& winsat.exe disk -ran -read -drive $env:SystemDrive.TrimEnd(':') 2>&1 | Out-String)
        Save-Raw 'winsat-disk.txt' ($o1 + $o2)
        $seq = $null; $ran = $null
        if ($o1 -match 'Sequential[^\r\n]*?([\d.,]+)\s*MB/s') { $seq = [double]($Matches[1] -replace ',', '.') }
        if ($o2 -match 'Random[^\r\n]*?([\d.,]+)\s*MB/s') { $ran = [double]($Matches[1] -replace ',', '.') }
        if ($seq) {
            $sysDisk = Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':') -ErrorAction SilentlyContinue | Get-Disk -ErrorAction SilentlyContinue | Get-PhysicalDisk -ErrorAction SilentlyContinue
            $bus = "$($sysDisk.BusType)"; $media = "$($sysDisk.MediaType)"
            $min = 60; if ($bus -eq 'NVMe') { $min = 900 } elseif ($media -eq 'SSD') { $min = 300 }
            $d = "Sequential read: {0:N0} MB/s   Random read: {1:N0} MB/s   ({2} {3})" -f $seq, $ran, $bus, $media
            if ($seq -lt $min) { Add-R $cat 'Disk speed' WARN $d "Slower than expected for this drive type (expected > $min MB/s). Can mean a worn/failing drive, a cheap drive or a background process." } else { Add-R $cat 'Disk speed' PASS $d }
        } else { Add-R $cat 'Disk speed' INFO 'Disk benchmark did not return a result.' }
    }
    if ($script:HasNative) {
        $free = [double]((Get-Cim Win32_OperatingSystem).FreePhysicalMemory) * 1KB
        $mb = [int][math]::Min(4096, [math]::Floor(($free * 0.4) / 1MB / 64) * 64)
        if ($mb -ge 256) {
            Write-Host "   RAM pattern test on $mb MB..." -ForegroundColor DarkGray
            $err = [LcStress]::MemTest($mb)
            if ($err -eq 0) { Add-R $cat 'Quick RAM test' PASS "$([LcStress]::TestedMB) MB tested with 5 patterns - no errors." 'Only part of the RAM can be tested while Windows runs.' }
            else { Add-R $cat 'Quick RAM test' FAIL "$err memory errors in $([LcStress]::TestedMB) MB!" 'The RAM is faulty. Do not buy (or price in new RAM if it is not soldered).' }
        }
    }
    if (-not $SkipStress -and $script:HasNative) {
        Write-Host "   CPU full-load test for $StressSeconds s - the fans should speed up..." -ForegroundColor DarkGray
        $idle = Get-Cim Win32_PerfFormattedData_Counters_ProcessorInformation 'root\cimv2' "Name='_Total'"
        $idleMHz = if ($idle) { [double]$idle.ProcessorFrequency * [double]$idle.PercentProcessorPerformance / 100 } else { 0 }
        $samples = @(); $temps = @(); $loads = @()
        [LcStress]::Start([int]$script:CpuThreads)
        try {
            $end = (Get-Date).AddSeconds($StressSeconds)
            while ((Get-Date) -lt $end) {
                Start-Sleep -Seconds 3
                $pi = Get-Cim Win32_PerfFormattedData_Counters_ProcessorInformation 'root\cimv2' "Name='_Total'"
                if ($pi) { $samples += [double]$pi.ProcessorFrequency * [double]$pi.PercentProcessorPerformance / 100; $loads += [double]$pi.PercentProcessorTime }
                $tz = @(Get-Cim MSAcpi_ThermalZoneTemperature 'root\wmi')
                if ($tz.Count) { $temps += (($tz | ForEach-Object { ($_.CurrentTemperature / 10) - 273.15 }) | Measure-Object -Maximum).Maximum }
            }
        } finally { [LcStress]::Stop() }
        if ($samples.Count) {
            $avg = ($samples | Measure-Object -Average).Average
            $last = ($samples | Select-Object -Last 3 | Measure-Object -Average).Average
            $ld = ($loads | Measure-Object -Average).Average
            $d = "Base clock: {0:N0} MHz   Idle: {1:N0} MHz`nUnder full load: average {2:N0} MHz, end of test {3:N0} MHz   (CPU load {4:N0}%)" -f $script:CpuBase, $idleMHz, $avg, $last, $ld
            if ($temps.Count) { $d += ("`nACPI temperature: max {0:N0} C" -f ($temps | Measure-Object -Maximum).Maximum) }
            $d += "`nOn charger: $($script:OnAC)"
            $ratio = if ($script:CpuBase -gt 0) { $last / $script:CpuBase } else { 1 }
            if ($ratio -lt 0.6) { Add-R $cat 'CPU under full load' WARN $d $(if (-not $script:OnAC) { 'CPU slows down a lot under load - but the laptop is on battery. Plug in and run again.' } else { 'CPU slows down a lot under load (thermal throttling). Typical causes: dust-clogged fan, dried thermal paste, weak charger, or a power-saving mode. Listen to the fan.' })
            }
            else { Add-R $cat 'CPU under full load' PASS $d 'Also listen: the fan should spin up smoothly without grinding or rattling, and the laptop should not shut down.' }
            if ($temps.Count -and ($temps | Measure-Object -Maximum).Maximum -ge 95) { Add-R $cat 'Temperature under load' WARN ("Reached {0:N0} C." -f ($temps | Measure-Object -Maximum).Maximum) 'Very hot - cooling needs cleaning / new thermal paste.' }
        } else { Add-R $cat 'CPU under full load' INFO 'CPU load test ran, but clock speed could not be measured on this system.' }
        Add-R $cat 'Fan noise' MANUAL 'Listen during the CPU test.' 'Grinding, clicking or a fan that never spins up = fan problem. A fan that is always loud even at rest = dust/thermal paste.'
    }
}

Invoke-Section 'Optional Sysinternals deep check (Tools folder)' {
    $cat = 'Deep check'
    $tools = Join-Path $here 'Tools'
    $have = @('autorunsc64.exe', 'sigcheck64.exe') | Where-Object { Test-Path (Join-Path $tools $_) }
    if ($have.Count -lt 2 -and $script:Online -and -not $NoPrompt) {
        $ans = Read-Host '   Download Microsoft Sysinternals Autoruns + Sigcheck (~3 MB, from live.sysinternals.com) for a deeper malware check? [y/N]'
        if ($ans -match '^\s*[yY]') {
            New-Item -ItemType Directory -Path $tools -Force | Out-Null
            foreach ($t in @('autorunsc64.exe', 'sigcheck64.exe')) {
                $dst = Join-Path $tools $t
                if (Test-Path $dst) { continue }
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    (New-Object System.Net.WebClient).DownloadFile("https://live.sysinternals.com/$t", $dst)
                    Write-Host "   downloaded $t" -ForegroundColor DarkGray
                } catch { Write-Host "   could not download $t : $($_.Exception.Message)" -ForegroundColor Yellow }
            }
        }
    }
    foreach ($t in @(Get-ChildItem $tools -Filter *.exe -ErrorAction SilentlyContinue)) {
        $s = Get-AuthenticodeSignature -LiteralPath $t.FullName
        if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Add-R $cat "Tool not trusted: $($t.Name)" WARN "Signature: $($s.Status) $($s.SignerCertificate.Subject)" 'This file in the Tools folder is not genuinely signed by Microsoft, so it was NOT run. Delete it and download it again from Microsoft.'
            Rename-Item -LiteralPath $t.FullName -NewName ($t.Name + '.untrusted') -ErrorAction SilentlyContinue
        }
    }
    $ar = @('autorunsc64.exe', 'autorunsc.exe') | ForEach-Object { Join-Path $tools $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
    $sc = @('sigcheck64.exe', 'sigcheck.exe') | ForEach-Object { Join-Path $tools $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ar -and -not $sc) { Add-R $cat 'Sysinternals tools' INFO 'Not used (put autorunsc64.exe and sigcheck64.exe from Microsoft Sysinternals into the Tools folder to enable VirusTotal-backed checks).'; return }
    $useVT = $false
    if ($script:Online) {
        if ($NoPrompt) { $useVT = $true } else { $ans = Read-Host '   Check auto-start files with VirusTotal? Only file fingerprints (hashes) are sent, no files. [Y/n]'; $useVT = ($ans -notmatch '^\s*[nN]') }
    }
    if ($ar) {
        Write-Host '   running Autoruns (all auto-start locations)...' -ForegroundColor DarkGray
        $argsA = @('-accepteula', '-nobanner', '-a', '*', '-c', '-h', '-s', '-m', '*')
        if ($useVT) { $argsA = @('-accepteula', '-nobanner', '-a', '*', '-c', '-h', '-s', '-m', '-vt', '*') }
        $csvPath = Join-Path $script:RawDir 'autoruns.csv'
        & $ar @argsA 2>$null | Out-File -FilePath $csvPath -Encoding utf8
        $rows = @(); try { $rows = @(Import-Csv $csvPath) } catch {}
        $unsigned = @($rows | Where-Object { $_.Signer -match 'Not verified' -and $_.'Image Path' })
        $vtCol = ($rows | Select-Object -First 1).PSObject.Properties.Name | Where-Object { $_ -match 'VT detection' } | Select-Object -First 1
        $vtBad = @(); if ($vtCol) { $vtBad = @($rows | Where-Object { $_.$vtCol -match '^(\d+)\|' -and [int]$Matches[1] -ge 2 }) }
        $vtOne = @(); if ($vtCol) { $vtOne = @($rows | Where-Object { $_.$vtCol -match '^1\|' }) }
        if ($vtBad.Count) { Add-R $cat 'VirusTotal: flagged auto-start files' FAIL (Join-Lines ($vtBad | ForEach-Object { "$($_.Entry) - $($_.'Image Path') - detections $($_.$vtCol)" })) 'Several antivirus engines flag these files as malicious.' }
        if ($vtOne.Count) { Add-R $cat 'VirusTotal: single detections' WARN (Join-Lines ($vtOne | ForEach-Object { "$($_.Entry) - $($_.'Image Path') - $($_.$vtCol)" })) 'One engine flagged these - often a false alarm, but check.' }
        if ($unsigned.Count) { Add-R $cat 'Autoruns: unsigned auto-start entries' WARN (Join-Lines ($unsigned | ForEach-Object { "$($_.Category): $($_.Entry) - $($_.'Image Path')" })) 'Unsigned items that start automatically. Look up anything unknown.' }
        if (-not $vtBad.Count -and -not $unsigned.Count) { Add-R $cat 'Autoruns deep check' PASS "$($rows.Count) non-Microsoft auto-start entries checked, nothing unsigned$(if ($useVT) { ' or flagged by VirusTotal' })." }
        Add-Appendix 'Autoruns (non-Microsoft auto-start entries)' ($rows | Select-Object Category, Entry, 'Image Path', Signer, Company, $(if ($vtCol) { $vtCol } else { 'Version' }))
    }
    if ($sc) {
        Write-Host '   running Sigcheck on user folders (unsigned programs)...' -ForegroundColor DarkGray
        $all = @()
        foreach ($root in @("$env:SystemDrive\Users", $env:ProgramData)) {
            $argsS = @('-accepteula', '-nobanner', '-c', '-e', '-u', '-s', $root)
            if ($useVT) { $argsS = @('-accepteula', '-nobanner', '-c', '-e', '-u', '-s', '-vt', $root) }
            $tmp = Join-Path $script:RawDir ("sigcheck_" + ($root -replace '[^A-Za-z]', '') + '.csv')
            & $sc @argsS 2>$null | Out-File -FilePath $tmp -Encoding utf8
            try { $all += @(Import-Csv $tmp) } catch {}
        }
        $vtc = ($all | Select-Object -First 1).PSObject.Properties.Name | Where-Object { $_ -match 'VT detection' } | Select-Object -First 1
        $bad = @(); if ($vtc) { $bad = @($all | Where-Object { $_.$vtc -match '^(\d+)\|' -and [int]$Matches[1] -ge 2 }) }
        if ($bad.Count) { Add-R $cat 'VirusTotal: flagged programs in user folders' FAIL (Join-Lines ($bad | ForEach-Object { "$($_.Path) - $($_.$vtc)" })) 'Programs flagged as malicious by several antivirus engines.' }
        Add-R $cat 'Sigcheck: unsigned programs in Users/ProgramData' INFO "$($all.Count) unsigned executable(s) found (CSV in raw folder)."
    }
}

Invoke-Section 'Microsoft Defender malware scan' {
    $cat = 'Malware scan'
    if ($DefenderScan -eq 'None') { Add-R $cat 'Defender scan' INFO 'Skipped by choice.'; return }
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if (-not $mp -or -not $mp.AMServiceEnabled) { Add-R $cat 'Defender scan' INFO 'Microsoft Defender is not active (another antivirus is in charge) - scan skipped.' 'Use the installed antivirus to run a full scan.'; return }
    if ($script:Online) {
        Write-Host '   updating virus definitions...' -ForegroundColor DarkGray
        $j = Start-Job -ScriptBlock { try { Update-MpSignature -ErrorAction Stop; 'ok' } catch { $_.Exception.Message } }
        if (-not (Wait-Job $j -Timeout 150)) { Stop-Job $j }
        Remove-Job $j -Force -ErrorAction SilentlyContinue
    }
    $t0 = Get-Date
    $type = if ($DefenderScan -eq 'Full') { 'FullScan' } else { 'QuickScan' }
    Write-Host "   running Defender $type - please wait (this window will update when done)..." -ForegroundColor Yellow
    $ok = $true
    try { Start-MpScan -ScanType $type -ErrorAction Stop } catch {
        $mpc = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
        if (Test-Path $mpc) { $null = & $mpc -Scan -ScanType $(if ($type -eq 'FullScan') { 2 } else { 1 }) 2>&1 } else { $ok = $false; Add-R $cat 'Defender scan' INFO ("Scan could not start: " + $_.Exception.Message) }
    }
    if (-not $ok) { return }
    $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
    $new = @(); try { $new = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $t0.AddMinutes(-1) }) } catch {}
    if ($new.Count) {
        $names = @(); try { $all = @(Get-MpThreat -ErrorAction Stop); foreach ($n in $new) { $names += (($all | Where-Object { $_.ThreatID -eq $n.ThreatID } | Select-Object -First 1).ThreatName + ' - ' + (@($n.Resources) -join ', ')) } } catch {}
        Add-R $cat "Defender $type" FAIL ("Threats found in this scan:`n" + (Join-Lines $names)) 'Malware was found on this PC right now. Do not log into any accounts on it. If you still buy it, wipe and reinstall Windows completely.'
    } else { Add-R $cat "Defender $type" PASS "No threats found ($mins min)." $(if ($type -eq 'QuickScan') { 'A Quick scan checks the common hiding places. For maximum certainty run a Full scan (or Defender Offline scan) after buying.' } else { '' }) }
}
#endregion

if ($script:Own) {
Invoke-Section 'After-purchase to-do list' {
    $cat = 'After purchase'
    $tool = switch ($script:Brand) {
        'Dell' { 'Dell Command | Update (business models) or Dell SupportAssist' }
        'Lenovo' { 'Lenovo Vantage (or Lenovo System Update / Commercial Vantage on ThinkPads)' }
        'HP' { 'HP Support Assistant (or HP Image Assistant on business models)' }
        'ASUS' { 'MyASUS > Customer Support > Live Update' }
        'Acer' { 'Acer Care Center > Update' }
        'MSI' { 'MSI Center > Support > Live Update' }
        'Microsoft' { 'Windows Update (Surface firmware and drivers come through it)' }
        default { "the drivers / BIOS page on the $($script:Manufacturer) support website" }
    }
    $pending = $null
    if ($script:Online) {
        Write-Host '   checking Windows Update for missing updates (up to 2 min)...' -ForegroundColor DarkGray
        $j = Start-Job -ScriptBlock { try { $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $r = $s.Search('IsInstalled=0 and IsHidden=0 and Type=''Software'''); @($r.Updates | ForEach-Object { $_.Title }) } catch { 'ERR:' + $_.Exception.Message } }
        if (Wait-Job $j -Timeout 120) { $pending = @(Receive-Job $j) } else { Stop-Job $j }
        Remove-Job $j -Force -ErrorAction SilentlyContinue
    }
    if ($pending -and "$($pending[0])" -like 'ERR:*') { $pending = $null }
    if ($null -ne $pending) {
        if ($pending.Count) { Add-R $cat 'Windows updates waiting' WARN ("$($pending.Count) update(s) not installed:`n" + (Join-Lines $pending 10)) 'Settings > Windows Update > Check for updates. Repeat until nothing is left (updates often come in rounds).' }
        else { Add-R $cat 'Windows updates' PASS 'Windows is fully up to date.' }
    }
    $prevOwner = @($script:Results | Where-Object { $_.Status -in 'FAIL', 'WARN' -and ($_.Category -in 'Suspicious software', 'Startup & persistence', 'Files', 'Company lock' -or $_.Check -match "Previous owner|Other user accounts|Hosts|Proxy|exclusions") })
    if ($prevOwner.Count) { Add-R $cat '1. Fresh start (strongly recommended)' MANUAL "This check found $($prevOwner.Count) item(s) left by the previous owner or that look risky (see red/yellow items)." 'Back up your own files, then Settings > System > Recovery > Reset this PC > Remove everything > Cloud download. Stay ONLINE during setup: if a company sign-in screen appears, stop and contact the seller (it is Autopilot-locked).' }
    else { Add-R $cat '1. Fresh start (optional)' MANUAL 'Nothing worrying was found, but you did not install this Windows yourself.' 'For full peace of mind: Settings > System > Recovery > Reset this PC > Remove everything > Cloud download.' }
    Add-R $cat '2. Update BIOS and drivers' MANUAL "Use $tool." 'Keep the charger plugged in and never interrupt a BIOS update. Afterwards enter the BIOS and confirm the CPU, RAM, drive and Secure Boot look right.'
    Add-R $cat '3. Warranty' MANUAL 'Register the serial number on the maker''s site and check whether the remaining warranty transfers to you.' 'Keep the seller''s receipt and this report as proof of condition on the day you got it.'
    Add-R $cat '4. Encryption + recovery key' MANUAL 'Turn on Device encryption / BitLocker and confirm the recovery key is saved to YOUR Microsoft account (account.microsoft.com/devices/recoverykey).' 'Without the key, a BIOS change or motherboard repair can lock you out of your files.'
    Add-R $cat '5. Recovery USB' MANUAL 'Make a Windows recovery drive: search "Create a recovery drive" (needs a 16+ GB USB stick).' 'Lets you repair or reinstall Windows if it ever stops booting.'
    Add-R $cat '6. Find My Device' MANUAL 'Settings > Privacy & security > Find my device > On (signed in with your Microsoft account).' 'Helps you locate or lock the laptop if it is lost or stolen.'
    if (@($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Category -notin 'After purchase' }).Count) { Add-R $cat '7. Problems found - act within the return window' MANUAL 'Red items were found. Most sellers/marketplaces (and consumer law for business sellers) give a limited return window.' 'Contact the seller now with this report (Report.html / Summary.txt). Do not attempt repairs yourself before they respond, as that can void a return.' }
    Add-R $cat '8. Track the battery and drive over time' MANUAL 'Run this check again in a month: the report compares battery health and drive wear with this run.' ''
    $bloat = @($script:Programs | Where-Object { $_.Name -match 'McAfee (LiveSafe|Total Protection|Security|Personal)|Norton (360|Security|AntiVirus)|WildTangent|ExpressVPN|Booking\.com|Dropbox (Promotion|offer)|Avast (Free|Premium)|AVG (AntiVirus|Internet)|CyberLink (Power|YouCam)|Candy Crush|Amazon (Alexa|Assistant)|Disney\+|Netflix|Spotify|TikTok|LinkedIn|Facebook|Instagram|Simple Solitaire|Bubble Witch' } | ForEach-Object { $_.Name } | Select-Object -Unique)
    if ($bloat.Count) { Add-R $cat 'Pre-installed / trial software you may not want' INFO (Join-Lines $bloat) 'Uninstall what you do not use (Settings > Apps). Two antivirus products at once slow the PC down - Microsoft Defender is enough for most people.' }
    if ($script:WantMemDiag) {
        $o = (& bcdedit.exe /bootsequence '{memdiag}' 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) { Add-R 'Memory' 'Full memory test scheduled' MANUAL 'Windows Memory Diagnostic will run at the NEXT restart (about 20 minutes, then Windows starts normally).' 'Run this tool again afterwards: it reads the result automatically (Memory > Last Windows Memory Diagnostic).' }
        else { Add-R 'Memory' 'Full memory test' INFO "Could not schedule: $o" 'Run mdsched.exe manually.' }
    }
}
}

if ($script:Sell) {
Invoke-Section 'Before selling - privacy & hand-over checklist' {
    $cat = 'Before selling'
    $lock = @($script:Results | Where-Object { $_.Category -eq 'Company lock' -and $_.Status -in 'FAIL', 'WARN' })
    if ($lock.Count) { Add-R $cat 'Fix the lock items first' FAIL ("$($lock.Count) company-lock / BIOS item(s) found - see the Company lock section.") 'A buyer will return (or open an eBay case on) a laptop that is managed, Autopilot-registered or BIOS-password protected. Remove these before listing.' }
    Add-R $cat '1. Do the hands-on tests' MANUAL 'Open ManualTests.html: screen, keyboard, touchpad, speakers, microphone, webcam.' 'Then tick the matching lines in the HANDS-ON part of Listing.txt (or delete the lines you could not test).'
    Add-R $cat '2. Take photos' MANUAL 'Photograph the laptop from all sides, the screen showing a white page, the keyboard, the serial sticker (cover part of it if you prefer), the charger label, and this report''s summary box.' 'Honest photos of any marks protect you from "not as described" returns.'
    Add-R $cat '3. Back up your files' MANUAL 'Copy everything you want to keep to another drive or cloud storage.' ''
    Add-R $cat '4. Sign out of everything' MANUAL 'Browsers (turn off Chrome/Edge sync), OneDrive, Office (account.microsoft.com/services > deactivate this PC), Steam / Epic / Adobe / iTunes (deauthorise), password managers.' 'Licences tied to this PC can then be used on your next one.'
    Add-R $cat '5. Unlink the PC from your Microsoft account' MANUAL 'Settings > Privacy & security > Find my device: Off. Then account.microsoft.com/devices > this PC > Remove.' ''
    Add-R $cat '6. Remove any BIOS password you set' MANUAL 'Enter the BIOS and clear admin / power-on passwords.' 'A buyer cannot remove it and will return the laptop.'
    Add-R $cat '7. Wipe it properly' MANUAL 'Settings > System > Recovery > Reset this PC > Remove everything > Cloud download > Change settings > Clean data = ON > Reset.' '"Clean data" overwrites the drive so your files cannot be recovered (takes 1-2 hours). It also removes BitLocker and your accounts.'
    Add-R $cat '8. Stop at the first setup screen' MANUAL 'When the reset finishes and shows "Is this the right country or region?", hold the power button to switch off.' 'The buyer then gets a fresh "new PC" setup with their own account.'
    Add-R $cat '9. Keep this report' MANUAL 'Keep the report folder (on the USB stick) after you wipe the laptop.' 'It proves the condition at sale if a buyer disputes it later.'
}
}

#region ===================== report =====================
try { [GC]::Collect(); [GC]::WaitForPendingFinalizers() } catch {}
foreach ($h in $script:MountedHives) { $null = & reg.exe unload "HKU\$h" 2>&1 }

Add-R 'Manual tests' 'Hands-on hardware tests' MANUAL 'Open ManualTests.html (button at the top of this report): screen, keyboard, touchpad, speakers, microphone, webcam and a physical inspection checklist.' 'Do these - software cannot see a cracked hinge, a sticky key or a buzzing speaker.'

# --- history: compare with earlier runs on the same machine ---
$histFile = Join-Path $OutRoot 'history.csv'
$prev = $null
try { if (Test-Path $histFile) { $prev = @(Import-Csv $histFile | Where-Object { $_.Serial -eq $script:Serial -and $_.Model -eq $script:Model }) | Select-Object -Last 1 } } catch {}
if ($prev) {
    $lines = @("Previous check: $($prev.Date) ($($prev.Mode) mode)")
    $st = 'INFO'
    if ($prev.BatteryHealth -and $script:Metrics['BatteryHealth']) {
        $dh = [double]$script:Metrics['BatteryHealth'] - [double]$prev.BatteryHealth
        $lines += ("Battery health: {0}% -> {1}% ({2:+0.0;-0.0;0} points)" -f $prev.BatteryHealth, $script:Metrics['BatteryHealth'], $dh)
        if ($prev.BatteryCycles -and $script:Metrics['BatteryCycles']) { $lines += "Battery cycles: $($prev.BatteryCycles) -> $($script:Metrics['BatteryCycles'])" }
        $days = [math]::Max(1, ((Get-Date) - [datetime]$prev.Date).TotalDays)
        if ($dh -lt -5 -and $days -lt 120) { $st = 'WARN'; $lines += 'Battery is losing capacity unusually fast.' }
    }
    if ($prev.DriveWear -ne '' -and $null -ne $script:Metrics['DriveWear']) { $lines += "Drive wear: $($prev.DriveWear)% -> $($script:Metrics['DriveWear'])%" }
    if ($prev.DrivePowerOnHours -and $script:Metrics['DrivePowerOnHours']) { $lines += "Drive powered-on hours: $($prev.DrivePowerOnHours) -> $($script:Metrics['DrivePowerOnHours'])" }
    $lines += "Problems / warnings then: $($prev.Problems) / $($prev.Warnings)"
    Add-R 'Identity' 'Compared with last check' $st ($lines -join "`n") $(if ($st -eq 'WARN') { 'Keep an eye on it; a battery losing several % per month may be faulty (check warranty).' } else { '' })
}

$AllRes = @($script:Results)
$fails = @($AllRes | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($AllRes | Where-Object { $_.Status -eq 'WARN' })
$passes = @($AllRes | Where-Object { $_.Status -eq 'PASS' })
$manual = @($AllRes | Where-Object { $_.Status -eq 'MANUAL' })
$lockFails = @($fails | Where-Object { $_.Category -eq 'Company lock' })
if ($script:Own) {
    if ($lockFails.Count) { $vClass = 'fail'; $vTitle = 'This laptop is still tied to an organisation'; $vText = 'Contact the seller now: the company must release it (Entra ID / Intune / Autopilot / BIOS lock). If they cannot, return it within your return window - it can be locked remotely or after a reset.' }
    elseif ($fails.Count) { $vClass = 'fail'; $vTitle = 'Problems found on your laptop'; $vText = 'Read the red items. Hardware faults: contact the seller / use your return window or warranty. Software issues: a fresh reset usually fixes them.' }
    elseif ($warns.Count) { $vClass = 'warn'; $vTitle = 'Healthy overall - a few things to tidy up'; $vText = 'Work through the yellow items and the After-purchase to-do list.' }
    else { $vClass = 'pass'; $vTitle = 'Your laptop looks healthy'; $vText = 'Finish the hands-on tests and the After-purchase to-do list.' }
} elseif ($script:Sell) {
    $hwFails = @($fails | Where-Object { $_.Category -notin 'Before selling', 'Company lock' })
    if ($lockFails.Count) { $vClass = 'fail'; $vTitle = 'Not ready to sell - remove the lock items first'; $vText = 'Buyers will return a laptop that is company-managed or BIOS-locked. Fix the red Company lock items, then run this again.' }
    elseif ($hwFails.Count) { $vClass = 'warn'; $vTitle = 'Ready to list - with known issues'; $vText = 'Your listing text below already lists the problems found. Being upfront avoids "not as described" returns. Do the before-selling checklist, then wipe the laptop.' }
    else { $vClass = 'pass'; $vTitle = 'Ready to list'; $vText = 'Copy the listing text below into eBay, do the hands-on tests and the before-selling checklist, then wipe the laptop.' }
} else {
    if ($lockFails.Count) { $vClass = 'fail'; $vTitle = 'STOP - this PC looks locked to or managed by an organisation'; $vText = 'Do not pay until the seller proves it has been released (removed from the company''s Entra ID / Intune / Autopilot / BIOS lock) and you have seen a clean reset.' }
    elseif ($fails.Count) { $vClass = 'fail'; $vTitle = 'Serious problems found'; $vText = 'Read every red item below before deciding. Use them to walk away or to negotiate the price.' }
    elseif ($warns.Count) { $vClass = 'warn'; $vTitle = 'No deal-breakers found - review the warnings'; $vText = 'Check each yellow item, then do the manual tests.' }
    else { $vClass = 'pass'; $vTitle = 'Automatic checks look good'; $vText = 'Finish the manual tests and the physical inspection before you pay.' }
}
$score = [math]::Max(0, 100 - 12 * $fails.Count - 3 * $warns.Count)
if ($lockFails.Count) { $score = [math]::Min($score, 20) }
try {
    $row = [pscustomobject]([ordered]@{ Date = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Mode = $Mode; Serial = $script:Serial; Model = $script:Model; Manufacturer = $script:Manufacturer; Score = $score; Problems = $fails.Count; Warnings = $warns.Count; BatteryHealth = $script:Metrics['BatteryHealth']; BatteryCycles = $script:Metrics['BatteryCycles']; BatteryFull_mWh = $script:Metrics['BatteryFull_mWh']; DriveWear = $script:Metrics['DriveWear']; DrivePowerOnHours = $script:Metrics['DrivePowerOnHours']; Report = $script:OutDir })
    $row | Export-Csv -Path $histFile -Append -NoTypeInformation -Encoding UTF8 -Force
} catch {}
$elapsed = [math]::Round(((Get-Date) - $script:Start).TotalMinutes, 1)

# --- eBay listing (sell mode) ---
$listingTxt = $null; $listingTitle = $null
if ($script:Sell) {
    function RS([string]$c) { $AllRes | Where-Object { $_.Check -eq $c } | Select-Object -First 1 }
    $okM = [string][char]0x2714
    $specs = New-Object System.Collections.ArrayList
    $tests = New-Object System.Collections.ArrayList
    $issues = New-Object System.Collections.ArrayList
    [void]$specs.Add(@('Model', "$($script:Manufacturer) $($script:FriendlyModel)"))
    [void]$specs.Add(@('Processor', $script:CpuName))
    if ($script:Spec['RAM']) { [void]$specs.Add(@('Memory (RAM)', $script:Spec['RAM'])) }
    foreach ($d in $script:SpecDrives) { [void]$specs.Add(@('Storage', $d.Label)) }
    foreach ($g in ($script:GpuNames | Select-Object -Unique)) { [void]$specs.Add(@('Graphics', $g)) }
    $scr = (@($script:Spec['ScreenSize'], $script:Spec['Res']) | Where-Object { $_ }) -join ', '
    if ($script:Spec['Hz'] -and [int]$script:Spec['Hz'] -gt 60) { $scr += " $($script:Spec['Hz']) Hz" }
    if ($scr) { [void]$specs.Add(@($(if ($script:IsLaptop) { 'Screen' } else { 'Display output' }), $scr)) }
    $wl = @(); if ($script:Spec['WiFi']) { $wl += $script:Spec['WiFi'] }; if ((RS 'Bluetooth').Status -eq 'PASS') { $wl += 'Bluetooth' }
    if ($wl.Count) { [void]$specs.Add(@('Wireless', ($wl -join ', '))) }
    if ($script:Spec['Windows']) { [void]$specs.Add(@('Operating system', $script:Spec['Windows'])) }

    function T([string]$check, [string]$okText) { $r = RS $check; if ($r -and $r.Status -eq 'PASS') { [void]$tests.Add($okText) } }
    if ($null -ne $script:Metrics['BatteryHealth']) {
        $bh = RS 'Battery health'
        $cyc = if ($script:Metrics['BatteryCycles'] -gt 0) { ", $($script:Metrics['BatteryCycles']) charge cycles" } else { '' }
        $word = switch ($bh.Status) { 'PASS' { 'good' } 'WARN' { 'worn - shorter run-time than new' } default { 'heavily worn - needs replacing' } }
        [void]$tests.Add("Battery health: $($script:Metrics['BatteryHealth'])% of original capacity$cyc ($word)")
    }
    T 'Charger & charging port' 'Charges normally with the charger'
    $rtR = RS 'Battery run-time'; if ($rtR -and $rtR.Status -eq 'PASS' -and $rtR.Detail -match 'full charge at this load: ([\d.,]+) hours') { [void]$tests.Add("Battery run-time measured: about $($Matches[1]) hours at light use") }
    foreach ($d in $script:SpecDrives) { if ($d.Status -in 'PASS', 'INFO') { [void]$tests.Add("Drive health ($($d.Label)): $($d.Health), no errors") } }
    $ds = RS 'Disk speed'; if ($ds -and $ds.Status -eq 'PASS' -and $ds.Detail -match 'Sequential read: ([\d,.]+) MB/s') { [void]$tests.Add("Drive speed: $($Matches[1]) MB/s read") }
    T 'Quick RAM test' 'Memory (RAM) test: passed, no errors'
    T 'CPU under full load' 'Full-load processor stress test: passed (no overheating or throttling)'
    if (@($AllRes | Where-Object { $_.Category -eq 'Graphics' -and $_.Status -eq 'FAIL' }).Count -eq 0 -and $script:GpuNames.Count) { [void]$tests.Add('Graphics: working, no driver or hardware errors') }
    T 'Wi-Fi' 'Wi-Fi: working'
    T 'Bluetooth' 'Bluetooth: working'
    $hw = @('Webcam', 'Microphone', 'Speakers / audio chip', 'Keyboard', 'Touchpad', 'Touch screen', 'Fingerprint / face sign-in', 'SD card reader', 'USB controllers') | Where-Object { (RS $_).Status -eq 'PASS' } | ForEach-Object { ($_ -replace ' / audio chip', '' -replace ' controllers', ' ports' -replace 'Fingerprint / face sign-in', 'fingerprint/face sign-in').ToLower() -replace '\busb\b', 'USB' -replace '\bsd\b', 'SD' }
    if (@($hw).Count) { [void]$tests.Add('Detected and working in Windows: ' + (@($hw) -join ', ')) }
    T 'Device Manager' 'All internal devices working (no driver errors)'
    if ((RS 'Blue screens (crashes)').Status -eq 'PASS' -and (RS 'Hardware errors (WHEA)').Status -eq 'PASS') { [void]$tests.Add('No crashes or hardware errors logged in the last 120 days') }
    if ($lockFails.Count -eq 0 -and @($AllRes | Where-Object { $_.Category -eq 'Company lock' -and $_.Status -eq 'WARN' }).Count -eq 0) { [void]$tests.Add('Not locked: no company management / Intune / Autopilot, no BIOS password, no anti-theft lock') }
    $wa = RS 'Windows activation'; if ($wa -and $wa.Status -eq 'PASS') { $t = 'Genuine Windows, activated'; if ((RS 'Licence key built into firmware').Status -eq 'PASS') { $t += ' (licence key built into the laptop - reinstalls activate automatically)' }; [void]$tests.Add($t) }
    if ((RS 'Secure Boot').Status -eq 'PASS' -and (RS 'TPM security chip').Status -eq 'PASS') { [void]$tests.Add('TPM 2.0 and Secure Boot enabled') }
    $mal = @($AllRes | Where-Object { $_.Category -eq 'Malware scan' -and $_.Check -like 'Defender*' } | Select-Object -First 1)
    if ($mal.Count -and $mal[0].Status -eq 'PASS') { [void]$tests.Add("Virus scan: clean ($($mal[0].Check -replace 'Defender ', 'Microsoft Defender ' -replace 'QuickScan', 'quick scan' -replace 'FullScan', 'full scan'))") }
    $partsR = @($AllRes | Where-Object { $_.Category -eq 'Parts' -and $_.Status -ne 'MANUAL' })
    $upg = @()
    if (@($partsR | Where-Object { $_.Check -eq 'Upgraded memory' }).Count) { $upg += 'RAM upgraded (retail module)' }
    if (@($partsR | Where-Object { $_.Check -eq 'Drive is original' -and $_.Status -eq 'INFO' }).Count) { $upg += 'SSD upgraded (retail drive)' }
    if ($upg.Count) { [void]$tests.Add('Upgrades: ' + ($upg -join ', ')) }
    elseif ($partsR.Count -and @($partsR | Where-Object { $_.Status -in 'WARN', 'FAIL' }).Count -eq 0) { [void]$tests.Add('No signs of replaced parts (' + $(if ($script:BatList.Count) { 'memory, drive and battery look original' } else { 'memory and drive look original' }) + ')') }
    $devWord = if ($script:IsLaptop) { 'laptop' } else { 'PC' }

    $hwCats = @('Storage', 'Memory', 'Processor', 'Graphics', 'Screen', 'Wireless', 'Other hardware', 'Devices', 'Stability', 'Performance', 'Parts', 'Battery')
    foreach ($r in ($AllRes | Where-Object { $_.Status -in 'FAIL', 'WARN' -and ($hwCats -contains $_.Category -or ($_.Category -eq 'Windows licence' -and $_.Status -eq 'FAIL')) -and $_.Check -ne 'Battery health' })) {
        $first = ("$($r.Detail)" -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        [void]$issues.Add("$($r.Check): $(Short $first 150)")
    }
    $cpuShort = ''; if ($script:CpuName -match '(i[3579]-\w+|Ryzen\s+\d\s+\w+|Core\s+Ultra\s+\d\s+\w+|Ultra\s+\d\s+\w+|Snapdragon\s+X\s+\w+(\s+\w+)?|Celeron\s+\w+|Pentium\s+\w+)') { $cpuShort = $Matches[1] -replace '\s+', ' ' }
    $stor = ($script:SpecDrives | Select-Object -First 1).Label -replace ' NVMe', '' -replace 'hard drive \(HDD\)', 'HDD'
    $gpuShort = ($script:GpuNames | Where-Object { $_ -match 'RTX|GTX|RX \d|Arc' } | Select-Object -First 1) -replace 'NVIDIA GeForce ', '' -replace 'AMD Radeon ', '' -replace ' Laptop GPU', '' -replace ' OEM', ''
    $mfr = ($script:Manufacturer -replace ' Inc\.?| Corporation|, Inc\.?| Co\.,? ?Ltd\.?|ASUSTeK COMPUTER INC\.', '').Trim()
    if ($mfr -match '^ASUSTeK') { $mfr = 'ASUS' }
    $mdl = ($script:FriendlyModel -replace '\s*\(type .*\)', '' -replace ('(?i)\s*\bby\s+' + [regex]::Escape($mfr) + '\b'), '' -replace '\s+\S*(xxx|0x)\S*$', '' -replace ('(?i)^' + [regex]::Escape($mfr) + '\s+'), '').Trim()
    $head = "$mfr $mdl".Trim()
    if ($head.Length -gt 38) { $head = $head.Substring(0, 38).Trim() }
    $cand = @($cpuShort, $(if ($script:Spec['RAM']) { (($script:Spec['RAM'] -split ' ')[0..1] -join '') + ' RAM' }), $stor, $gpuShort, $(if ($script:Spec['Windows'] -match 'Windows 11') { 'Win 11' } elseif ($script:Spec['Windows'] -match 'Windows 10') { 'Win 10' })) | Where-Object { $_ -and "$_".Trim() }
    $listingTitle = $head
    foreach ($c in $cand) { if (("$listingTitle | $c | Tested").Length -le 80) { $listingTitle += " | $c" } }
    if (("$listingTitle | Tested").Length -le 80) { $listingTitle += ' | Tested' }

    $tx = New-Object System.Collections.Generic.List[string]
    $tx.Add("SUGGESTED TITLE (max 80 characters): $listingTitle"); $tx.Add(''); $tx.Add('==================== DESCRIPTION ===================='); $tx.Add('')
    $tx.Add("$($script:Manufacturer) $($script:FriendlyModel)"); $tx.Add('')
    $tx.Add('SPECIFICATIONS'); foreach ($s in $specs) { $tx.Add("- $($s[0]): $($s[1])") }; $tx.Add('')
    $tx.Add("TESTED ON $((Get-Date).ToString('d MMMM yyyy')) - full automated hardware, health and security check")
    foreach ($t in $tests) { $tx.Add("$okM $t") }; $tx.Add('')
    $tx.Add('KNOWN ISSUES'); if ($issues.Count) { foreach ($i in $issues) { $tx.Add("- $i") } } else { $tx.Add('- None found by the automated tests.') }; $tx.Add('')
    $tx.Add('HANDS-ON CHECKS (tick what you checked, delete what you did not)')
    foreach ($h in @('Screen: no dead pixels, no backlight bleed, no lines', 'Keyboard: every key works', 'Touchpad: clicks and gestures work', 'Speakers and headphone jack work', 'Webcam and microphone work', 'All USB / USB-C / HDMI ports work', 'Hinges firm, no cracks')) { if ($script:IsLaptop -or $h -notmatch 'Touchpad|Hinges|Webcam') { $tx.Add("[ ] $h") } }
    $tx.Add(''); $tx.Add('COSMETIC CONDITION: (describe scratches / marks - match your photos)')
    $tx.Add($(if ($script:IsLaptop) { 'INCLUDED: (e.g. original charger ___ W, box)' } else { 'INCLUDED: (e.g. power cable, box)' })); $tx.Add('')
    $tx.Add("The $devWord will be fully wiped (Windows ""clean data"" reset) and left at the first-start screen, ready for the new owner. Full test report available on request.")
    $listingTxt = $tx -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $script:OutDir 'Listing.txt'), $listingTxt, (New-Object System.Text.UTF8Encoding($true)))
    $lh = New-Object System.Text.StringBuilder
    [void]$lh.Append("<div style=""font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#222;max-width:800px"">")
    [void]$lh.Append("<h2 style=""margin:0 0 12px"">$(HE "$($script:Manufacturer) $($script:FriendlyModel)")</h2>")
    [void]$lh.Append("<h3 style=""margin:16px 0 6px"">Specifications</h3><table style=""border-collapse:collapse"">")
    foreach ($s in $specs) { [void]$lh.Append("<tr><td style=""padding:3px 14px 3px 0;color:#555"">$(HE $s[0])</td><td style=""padding:3px 0""><b>$(HE $s[1])</b></td></tr>") }
    [void]$lh.Append("</table><h3 style=""margin:16px 0 6px"">Tested on $((Get-Date).ToString('d MMMM yyyy'))</h3><ul style=""margin:0;padding-left:20px"">")
    foreach ($t in $tests) { [void]$lh.Append("<li style=""margin:2px 0""><span style=""color:#1e8e4e"">&#10004;</span> $(HE $t)</li>") }
    [void]$lh.Append("</ul><h3 style=""margin:16px 0 6px"">Known issues</h3><ul style=""margin:0;padding-left:20px"">")
    if ($issues.Count) { foreach ($i in $issues) { [void]$lh.Append("<li>$(HE $i)</li>") } } else { [void]$lh.Append('<li>None found by the automated tests.</li>') }
    [void]$lh.Append("</ul><p style=""margin-top:16px"">The $devWord will be fully wiped (Windows &quot;clean data&quot; reset) and left at the first-start screen, ready for the new owner. Full test report available on request.</p></div>")
    [IO.File]::WriteAllText((Join-Path $script:OutDir 'Listing-eBay.html'), $lh.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

$manualRel = '../../ManualTests.html'
if (-not (Test-Path (Join-Path $here 'ManualTests.html')) -or -not $script:OutDir.StartsWith($here)) { $manualRel = 'file:///' + ((Join-Path $here 'ManualTests.html') -replace '\\', '/') }

$sb = New-Object System.Text.StringBuilder
function W([string]$s) { [void]$sb.Append($s) }
function Row($r) {
    $c = $r.Status.ToLower()
    W "<tr class='r-$c'><td><span class='badge $c'>$($r.Status)</span></td><td class='chk'>$(HE $r.Check)</td><td><div class='det'>$(HE $r.Detail)</div>"
    if ($r.Advice) { W "<div class='adv'>$(HE $r.Advice)</div>" }
    W '</td></tr>'
}
$css = @'
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6777;--line:#e2e6ec;--pass:#1e8e4e;--passbg:#e6f6ec;--warn:#a86500;--warnbg:#fff4dc;--fail:#c62828;--failbg:#fde8e8;--info:#4b5563;--infobg:#eef0f3;--man:#0b6aa8;--manbg:#e3f1fb;--acc:#2457d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#12151b;--card:#1b2029;--text:#e6e9ef;--muted:#9aa3b2;--line:#2b3240;--pass:#4cc27f;--passbg:#14301f;--warn:#f0b44c;--warnbg:#36290f;--fail:#ff6b6b;--failbg:#3a1717;--info:#b5bcc8;--infobg:#242a35;--man:#59b7f5;--manbg:#132b3d;--acc:#7ea2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 10px}.muted{color:var(--muted)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 18px;margin:14px 0;color:var(--muted);font-size:14px}.meta b{color:var(--text)}
.verdict{border-radius:12px;padding:18px 20px;margin:18px 0;border:2px solid}.verdict h2{margin:0 0 6px;font-size:22px}
.verdict.fail{background:var(--failbg);border-color:var(--fail)}.verdict.fail h2{color:var(--fail)}
.verdict.warn{background:var(--warnbg);border-color:var(--warn)}.verdict.warn h2{color:var(--warn)}
.verdict.pass{background:var(--passbg);border-color:var(--pass)}.verdict.pass h2{color:var(--pass)}
.counts{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}.counts span{padding:4px 12px;border-radius:20px;font-weight:600;font-size:14px}
.btn{display:inline-block;background:var(--acc);color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;margin:6px 8px 6px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:14px}
.card h3{margin:0;padding:12px 16px;font-size:16px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:8px}
table{width:100%;border-collapse:collapse}td,th{padding:10px 14px;vertical-align:top;border-bottom:1px solid var(--line);text-align:left}
tr:last-child td{border-bottom:0}td:first-child{width:86px}.chk{width:28%;font-weight:600}
.det{white-space:pre-wrap;word-break:break-word;font-size:14px}.adv{margin-top:6px;font-size:14px;color:var(--muted)}.adv:before{content:"What to do: ";font-weight:600;color:var(--text)}
.badge{display:inline-block;min-width:62px;text-align:center;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:.3px}
.pass{color:var(--pass);background:var(--passbg)}.warn{color:var(--warn);background:var(--warnbg)}.fail{color:var(--fail);background:var(--failbg)}.info{color:var(--info);background:var(--infobg)}.manual{color:var(--man);background:var(--manbg)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}summary{cursor:pointer;padding:10px 14px;font-weight:600}
.tablewrap{overflow-x:auto;max-height:520px;overflow-y:auto}.tablewrap table{font-size:13px}.tablewrap th{position:sticky;top:0;background:var(--card)}
.filter{margin:6px 0 14px;display:flex;gap:8px;flex-wrap:wrap}.filter label{font-size:14px;color:var(--muted)}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.chk{width:auto}td,th{padding:8px}td:first-child{width:70px}}
@media print{.btn,.filter{display:none}details{break-inside:avoid}details:not([open]) .tablewrap{display:none}}
'@
$rTitle = if ($script:Own) { 'My Laptop Health Report' } elseif ($script:Sell) { 'Laptop Sale Report' } else { 'Laptop Check Report' }
W "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>$rTitle</title><style>$css</style></head><body><div class='wrap'>"
W "<h1>$rTitle</h1><div class='muted'>$(HE $script:Manufacturer) $(HE $script:FriendlyModel) - $(if ($script:Own) { 'after-purchase check' } elseif ($script:Sell) { 'pre-sale check' } else { 'pre-purchase check' })</div>"
W "<div class='meta'><div>Serial: <b>$(HE $script:Serial)</b></div><div>Checked: <b>$((Get-Date).ToString('yyyy-MM-dd HH:mm'))</b></div><div>Windows: <b>$(HE $os.Caption) ($($os.BuildNumber))</b></div><div>Mode: <b>$(if ($script:IsAdmin) { 'Administrator - full' } else { 'LIMITED (not admin)' })</b></div><div>Duration: <b>$elapsed min</b></div><div>Tool: <b>v$($script:ToolVersion)</b></div></div>"
W "<div class='verdict $vClass'><h2>$(HE $vTitle)</h2><div>$(HE $vText)</div><div class='counts'><span class='info'>Score $score / 100</span><span class='fail'>$($fails.Count) problems</span><span class='warn'>$($warns.Count) warnings</span><span class='pass'>$($passes.Count) passed</span><span class='manual'>$($manual.Count) to check by hand</span></div></div>"
W "<a class='btn' href='$manualRel'>Open hands-on tests (screen, keyboard, speakers...)</a><a class='btn' href='battery-report.html'>Windows battery report</a>"
if ($listingTxt) {
    W "<h2>Your eBay listing</h2><div class='card' style='padding:16px'><p class='muted' style='margin-top:0'>Built from the real test results. Fill in the hands-on ticks, cosmetic condition and what is included. <b>Listing-eBay.html</b> (in this folder) is the same text with formatting: in eBay's description editor switch to HTML and paste it.</p>"
    W "<p><b>Suggested title:</b> <span id='lt'>$(HE $listingTitle)</span> <button onclick=""navigator.clipboard.writeText(document.getElementById('lt').textContent)"" class='btn' style='border:0;cursor:pointer;padding:4px 10px'>Copy title</button></p>"
    W "<textarea id='lst' style='width:100%;height:360px;font:13px/1.45 Consolas,monospace;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--text)'>$(HE $listingTxt)</textarea>"
    W "<button onclick=""navigator.clipboard.writeText(document.getElementById('lst').value);this.textContent='Copied!'"" class='btn' style='border:0;cursor:pointer'>Copy listing text</button><a class='btn' href='Listing-eBay.html'>Open formatted version</a></div>"
}
if (-not $script:IsAdmin) { W "<div class='verdict warn'><b>Limited mode:</b> the tool was not run as administrator, so drive health, BitLocker/TPM, Defender exclusions, other users' settings and some company-lock checks were skipped. Run it again and click <i>Yes</i> on the admin prompt.</div>" }
if ($fails.Count) { W "<h2>Problems (red)</h2><div class='card'><table>"; foreach ($r in $fails) { Row $r }; W '</table></div>' }
if ($warns.Count) { W "<h2>Warnings (yellow)</h2><div class='card'><table>"; foreach ($r in $warns) { Row $r }; W '</table></div>' }
if ($manual.Count) { W "<h2>Check these yourself</h2><div class='card'><table>"; foreach ($r in $manual) { Row $r }; W '</table></div>' }
W "<h2>All results by area</h2><div class='filter'><label><input type='checkbox' id='hidePass'> Hide passed and info rows</label></div>"
$order = @('Identity', 'Company lock', 'Windows licence', 'Firmware', 'Brand-specific', 'Battery', 'Storage', 'Memory', 'Processor', 'Graphics', 'Screen', 'Wireless', 'Other hardware', 'Devices', 'Stability', 'Accounts', 'Security', 'Suspicious software', 'Startup & persistence', 'Network', 'Files', 'Performance', 'Parts', 'Deep check', 'Malware scan', 'After purchase', 'Before selling', 'Manual tests')
$cats = @($order | Where-Object { $c = $_; @($AllRes | Where-Object { $_.Category -eq $c }).Count }) + @($AllRes | ForEach-Object { $_.Category } | Select-Object -Unique | Where-Object { $order -notcontains $_ })
foreach ($c in $cats) {
    $rs = @($AllRes | Where-Object { $_.Category -eq $c })
    $nf = @($rs | Where-Object { $_.Status -eq 'FAIL' }).Count; $nw = @($rs | Where-Object { $_.Status -eq 'WARN' }).Count
    $tag = if ($nf) { "<span class='badge fail'>$nf problem(s)</span>" } elseif ($nw) { "<span class='badge warn'>$nw warning(s)</span>" } else { "<span class='badge pass'>OK</span>" }
    W "<div class='card'><h3><span>$(HE $c)</span>$tag</h3><table>"
    foreach ($r in ($rs | Sort-Object @{ e = { @{ 'FAIL' = 0; 'WARN' = 1; 'MANUAL' = 2; 'INFO' = 3; 'PASS' = 4 }[$_.Status] } })) { Row $r }
    W '</table></div>'
}
if ($script:Appendix.Count) {
    W '<h2>Details / appendix</h2><p class="muted">Full lists behind the checks above. Look up anything you do not recognise.</p>'
    foreach ($k in $script:Appendix.Keys) {
        $rows = @($script:Appendix[$k])
        W "<details><summary>$(HE $k) ($($rows.Count))</summary><div class='tablewrap'><table><thead><tr>"
        $props = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($p in $props) { W "<th>$(HE $p)</th>" }
        W '</tr></thead><tbody>'
        foreach ($row in ($rows | Select-Object -First 3000)) { W '<tr>'; foreach ($p in $props) { W "<td>$(HE $row.$p)</td>" }; W '</tr>' }
        W '</tbody></table></div></details>'
    }
}
W "<footer><p><b>What this tool cannot see:</b> physical damage, liquid damage, a BIOS password on brands that hide it, firmware-level locks that only appear after a reset, whether the laptop is reported stolen, and malware hidden inside files (only the Defender scan reads file contents). Always do the manual tests, enter the BIOS, and ideally watch the seller reset the PC while online.</p><p>Raw data (logs, dsregcmd output, battery XML) is in the <i>raw</i> sub-folder.</p></footer>"
W "<script>document.getElementById('hidePass').addEventListener('change',function(e){document.querySelectorAll('tr.r-pass,tr.r-info').forEach(function(r){r.style.display=e.target.checked?'none':''})});</script>"
W '</div></body></html>'
$reportPath = Join-Path $script:OutDir 'Report.html'
[IO.File]::WriteAllText($reportPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
try { $AllRes | ConvertTo-Json -Depth 3 | Out-File (Join-Path $script:RawDir 'results.json') -Encoding utf8 } catch {}
$txt = @("LAPTOP CHECK - $($script:Manufacturer) $($script:FriendlyModel)  S/N $($script:Serial)", "Verdict: $vTitle", "Problems: $($fails.Count)  Warnings: $($warns.Count)  Passed: $($passes.Count)", '')
foreach ($r in ($fails + $warns)) { $txt += "[$($r.Status)] $($r.Category) - $($r.Check)"; $txt += ('    ' + ($r.Detail -replace "`n", "`n    ")); if ($r.Advice) { $txt += "    -> $($r.Advice)" }; $txt += '' }
$txt | Out-File (Join-Path $script:OutDir 'Summary.txt') -Encoding utf8

try { Stop-Transcript | Out-Null } catch {}
Write-Host ''
Write-Host '=================================================================' -ForegroundColor Cyan
$col = @{ fail = 'Red'; warn = 'Yellow'; pass = 'Green' }[$vClass]
Write-Host "  $vTitle" -ForegroundColor $col
Write-Host ("  Problems: {0}   Warnings: {1}   Passed: {2}   Manual checks: {3}" -f $fails.Count, $warns.Count, $passes.Count, $manual.Count)
Write-Host "  Report: $reportPath"
Write-Host '=================================================================' -ForegroundColor Cyan
if (-not $NoOpen) { try { Start-Process $reportPath } catch {} }
if (-not $NoPrompt) { [void](Read-Host 'Press Enter to close this window') }
#endregion
