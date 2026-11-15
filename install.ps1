<#
.SYNOPSIS
  conduit-tunnel installer (Windows). Downloads the signed binary, installs
  it as a Windows service (LocalSystem, automatic start), and starts it.
  Outbound-only -- opens no inbound port; the agent dials the WYRE relay
  over an outbound WSS tunnel.

.DESCRIPTION
  This is the Windows counterpart of install.sh. The Go binary knows how to
  *run* as a service (Service Control Manager dispatcher); this script owns
  service *management* -- create / configure / start / stop / remove -- exactly
  as install.sh owns the systemd unit on Linux.

  Configuration comes from parameters (so an RMM can set site variables and run
  this unattended). A Windows service receives RELAY_URL / ENROLLMENT_TOKEN /
  LOG_LEVEL from a per-service REG_MULTI_SZ 'Environment' value under the
  service's registry key; the binary reads them from its process environment at
  start. That key is admin/SYSTEM-only by default -- the Windows equivalent of
  install.sh's chmod 600 on the Linux env file.

  The binary writes its own logs to
  C:\ProgramData\conduit-tunnel\logs\conduit-tunnel.log.

.PARAMETER EnrollmentToken
  The identity-only enrollment JWT minted in Conduit (site -> Deploy connector).
  Required for install. Never written to the console, a transcript, or a log.

.PARAMETER RelayUrl
  The wss:// relay endpoint to dial. Default: wss://conduit-wss.wyre.ai.

.PARAMETER LogLevel
  debug | info | warn | error. Default: info.

.PARAMETER Version
  GitHub Release tag to pull the signed binary from. Default: latest.

.PARAMETER ConnectorUrl
  Direct URL to the tunnel .exe (air-gapped / self-provided override). If
  set, it is used instead of the GitHub Release URL.

.PARAMETER SkipSignatureCheck
  Skip Authenticode verification. Only for air-gapped / self-provided binaries.

.PARAMETER ServiceAccount
  Run the Windows service under this account instead of LocalSystem. Use a gMSA
  as `DOMAIN\gmsaname$` (note the trailing `$`; gMSA passwords are managed by
  Active Directory, so none is supplied). The gMSA must already be installed on
  this host (Install-ADServiceAccount) and this host authorized to use it -- that
  is an AD-admin prerequisite this installer does not perform. Enables `mssql`
  `auth:integrated` (no stored SQL credential).

.PARAMETER Uninstall
  Stop and remove the service and the install directory (logs are left in
  place), then exit.

.EXAMPLE
  # Unattended install (RMM):
  .\install.ps1 -EnrollmentToken '<jwt>' -RelayUrl 'wss://conduit-wss.wyre.ai'

.EXAMPLE
  # Air-gapped install from a self-provided binary:
  .\install.ps1 -EnrollmentToken '<jwt>' -ConnectorUrl 'https://.../conduit-tunnel-windows-amd64.exe' -SkipSignatureCheck

.EXAMPLE
  # Run the service under a gMSA (enables mssql auth:integrated -- no stored SQL credential):
  .\install.ps1 -EnrollmentToken '<jwt>' -ServiceAccount 'CONTOSO\conduitgmsa$'

.EXAMPLE
  # Remove:
  .\install.ps1 -Uninstall
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [string]$EnrollmentToken,

    [Parameter(ParameterSetName = 'Install')]
    [string]$RelayUrl = 'wss://conduit-wss.wyre.ai',

    [Parameter(ParameterSetName = 'Install')]
    [ValidateSet('debug', 'info', 'warn', 'error')]
    [string]$LogLevel = 'info',

    [Parameter(ParameterSetName = 'Install')]
    [string]$Version = 'latest',

    [Parameter(ParameterSetName = 'Install')]
    [string]$ConnectorUrl = '',

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipSignatureCheck,

    [Parameter(ParameterSetName = 'Install')]
    [string]$ServiceAccount = '',

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- constants (keep in lockstep with dispatch_windows.go / the LOCKED contract) ---
$ServiceName = 'conduit-tunnel'
$DisplayName = 'Conduit on-prem tunnel'
$Description = 'Reaches on-prem systems through Conduit over an outbound-only WSS tunnel. Binds no inbound port.'
$Repo        = 'WYRE-AI/conduit-tunnel'
$Asset       = 'conduit-tunnel-windows-amd64.exe'
$InstallDir  = Join-Path $env:ProgramFiles 'conduit-tunnel'          # C:\Program Files\conduit-tunnel
$BinPath     = Join-Path $InstallDir 'conduit-tunnel.exe'
$LogPath     = Join-Path $env:ProgramData 'conduit-tunnel\logs\conduit-tunnel.log'
$RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"    # per-service Environment lives here

# --- tiny helpers (mirror install.sh's "install: ..." / die) ---
function Write-Info { param([string]$Message) Write-Host "install: $Message" }
function Die        { param([string]$Message) throw "install: $Message" }

# --- explicit elevation check (clear message; #Requires also guards this) ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die 'must be run from an elevated (Administrator) PowerShell session.'
}

# ============================================================================
#  Uninstall: stop + delete the service, remove the install dir, leave logs.
# ============================================================================
if ($Uninstall) {
    Write-Info "uninstalling $ServiceName"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            try { $svc.WaitForStatus('Stopped', '00:00:30') } catch { }
        }
        # sc.exe delete works on Windows PowerShell 5.1 (Remove-Service is PS 6+).
        & sc.exe delete $ServiceName | Out-Null
    }
    else {
        Write-Info "service not present; nothing to stop"
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Info "done. Removed the service and $InstallDir."
    Write-Info "logs were left in place: $LogPath"
    exit 0
}

# ============================================================================
#  Install / upgrade
# ============================================================================

# --- preconditions (match the binary's own boot guards in main.go) ---
if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
    Die 'ENROLLMENT_TOKEN is required (mint it in Conduit: site -> Deploy connector).'
}
if ($RelayUrl -notlike 'wss://*') {
    Die "RELAY_URL must be wss:// -- TLS is not optional (got: $RelayUrl)."
}

# Prefer TLS 1.2+ for the download (Windows PowerShell 5.1 may default lower).
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch { }

# --- resolve the download URL ---
if (-not [string]::IsNullOrWhiteSpace($ConnectorUrl)) {
    $url = $ConnectorUrl
    Write-Info "downloading tunnel binary (direct URL)"
}
elseif ($Version -eq 'latest') {
    $url = "https://github.com/$Repo/releases/latest/download/$Asset"
    Write-Info "downloading $Asset (latest) from GitHub Releases"
}
else {
    $url = "https://github.com/$Repo/releases/download/$Version/$Asset"
    Write-Info "downloading $Asset ($Version) from GitHub Releases"
}

$tmpDir = $null
try {
    # --- fetch to a temp dir (once) ---
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("conduit-tunnel-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $tmpExe = Join-Path $tmpDir 'conduit-tunnel.exe'

    try {
        Invoke-WebRequest -Uri $url -OutFile $tmpExe -UseBasicParsing
    }
    catch {
        Die "download failed ($url): $($_.Exception.Message). For air-gapped hosts pass -ConnectorUrl."
    }
    if (-not (Test-Path $tmpExe) -or (Get-Item $tmpExe).Length -eq 0) {
        Die "downloaded binary is empty ($url)."
    }

    # --- verify Authenticode signature (Azure Artifact Signing; WYRE Technology, LLC) ---
    if ($SkipSignatureCheck) {
        Write-Warning "install: skipping Authenticode signature verification (-SkipSignatureCheck)."
    }
    else {
        $sig = Get-AuthenticodeSignature -FilePath $tmpExe
        if ($sig.Status -ne 'Valid') {
            Die "Authenticode signature is not Valid (status: $($sig.Status)). Refusing to install. Use -SkipSignatureCheck only for a self-provided/air-gapped binary."
        }
        $subject = $sig.SignerCertificate.Subject
        if ($subject -notlike '*WYRE Technology*') {
            Die "signer is not WYRE Technology (subject: $subject). Refusing to install."
        }
        Write-Info "signature verified: $subject"
    }

    # --- stop an existing service so the .exe isn't locked (upgrade-safe) ---
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Stopped') {
        Write-Info "stopping existing service for upgrade"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        try { $existing.WaitForStatus('Stopped', '00:00:30') } catch { }
    }

    # --- install the binary ---
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $tmpExe -Destination $BinPath -Force
    Write-Info "installed binary to $BinPath"

    # --- create or reconfigure the service (LocalSystem, automatic start) ---
    $binaryPathName = '"' + $BinPath + '"'   # quoted: the path contains a space
    if (-not $existing) {
        New-Service -Name $ServiceName `
            -BinaryPathName $binaryPathName `
            -DisplayName $DisplayName `
            -Description $Description `
            -StartupType Automatic | Out-Null
        Write-Info "created service $ServiceName (LocalSystem, automatic start)"
    }
    else {
        Set-Service -Name $ServiceName -StartupType Automatic -DisplayName $DisplayName
        # Description via sc.exe (Set-Service -Description is PS 6+); also refresh
        # the binary path in case the install location ever changes.
        & sc.exe config $ServiceName binPath= $binaryPathName start= auto | Out-Null
        & sc.exe description $ServiceName $Description | Out-Null
        Write-Info "reconfigured existing service $ServiceName"
    }

    # --- optional: run the service under a specific account instead of LocalSystem ---
    #     Set only when -ServiceAccount was given; otherwise the create/reconfigure
    #     above leaves the service as LocalSystem (the unchanged default). For a gMSA
    #     the logon account is DOMAIN\gmsa$ with NO password -- Active Directory
    #     manages the gMSA password, so none is stored here.
    #
    #     We use the Win32_Service.Change WMI/CIM method (NOT `sc.exe config obj=`):
    #     `sc.exe config ... password= ""` rejects the empty password with error 1639
    #     (ERROR_INVALID_COMMAND_LINE). Change() accepts an empty StartPassword
    #     cleanly and is authoritative for both a freshly created service and an
    #     in-place upgrade. Win32_Service is available on Windows PowerShell 5.1.
    if (-not [string]::IsNullOrWhiteSpace($ServiceAccount)) {
        # 1. Grant the account "Log on as a service" (SeServiceLogonRight). Setting
        #    the logon account programmatically does NOT grant this right (only the
        #    Services MMC does), so without it the service fails to start.
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($ServiceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $tmpInf = Join-Path $env:TEMP ("svclogon-" + [Guid]::NewGuid().ToString('N') + ".inf")
            $tmpDb  = [IO.Path]::ChangeExtension($tmpInf, 'sdb')
            & secedit /export /areas USER_RIGHTS /cfg $tmpInf | Out-Null
            $inf = Get-Content $tmpInf
            $line = $inf | Where-Object { $_ -match '^SeServiceLogonRight' }
            if (-not $line) { $line = 'SeServiceLogonRight = *S-1-5-80-0' }
            if ($line -notmatch [regex]::Escape($sid)) {
                $newLine = $line.TrimEnd() + ",*$sid"
                if ($inf -match '^SeServiceLogonRight') {
                    $inf = $inf | ForEach-Object { if ($_ -match '^SeServiceLogonRight') { $newLine } else { $_ } }
                } else {
                    $inf = $inf -replace '(\[Privilege Rights\])', "`$1`r`n$newLine"
                }
                Set-Content $tmpInf $inf -Encoding Unicode
                & secedit /configure /db $tmpDb /cfg $tmpInf /areas USER_RIGHTS | Out-Null
                Write-Info "granted 'Log on as a service' to $ServiceAccount"
            }
            Remove-Item $tmpInf, $tmpDb -ErrorAction SilentlyContinue
        } catch {
            Write-Info "could not auto-grant 'Log on as a service' to $ServiceAccount ($($_.Exception.Message)); grant SeServiceLogonRight manually if the service fails to start"
        }

        # 2. Point the service's logon account at the account (empty password = gMSA).
        $svcObj = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $chg = Invoke-CimMethod -InputObject $svcObj -MethodName Change -Arguments @{ StartName = $ServiceAccount; StartPassword = '' }
        if ($chg.ReturnValue -ne 0) {
            Die "setting the service logon account to $ServiceAccount failed (Win32_Service.Change returned $($chg.ReturnValue)). For a gMSA, confirm it is installed on this host (Install-ADServiceAccount) and that the host is authorized to use it."
        }
        Write-Info "service will run as $ServiceAccount (enables mssql auth:integrated -- no stored SQL credential)"
    }

    # --- write the service environment (REG_MULTI_SZ; admin/SYSTEM-only key -> the
    #     Windows equivalent of install.sh's chmod 600 env file). Piped to Out-Null
    #     so the token is never emitted to the pipeline/console. ---
    $envMulti = @(
        "RELAY_URL=$RelayUrl",
        "ENROLLMENT_TOKEN=$EnrollmentToken",
        "LOG_LEVEL=$LogLevel"
    )
    New-ItemProperty -Path $RegPath -Name 'Environment' -PropertyType MultiString -Value $envMulti -Force | Out-Null
    Write-Info "wrote service environment (RELAY_URL, ENROLLMENT_TOKEN, LOG_LEVEL)"

    # --- failure recovery: restart the process on a CRASH (unexpected
    #     termination), resetting the failure counter daily. We deliberately do
    #     NOT set the failure-actions flag (`sc.exe failureflag ... 1`), so a
    #     *graceful* non-zero exit -- e.g. the binary's fatal config guard on a
    #     missing/invalid RELAY_URL/ENROLLMENT_TOKEN -- is a terminal Stopped
    #     state and does NOT loop-restart every 5s. Transient network drops are
    #     absorbed inside the connector (reconnect with backoff), so they never
    #     reach this recovery path. ---
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Die "sc.exe failure returned $LASTEXITCODE while configuring restart-on-crash recovery."
    }
    Write-Info "configured restart-on-crash recovery"

    # --- start it ---
    Start-Service -Name $ServiceName
    Write-Info "service started"
}
finally {
    if ($tmpDir -and (Test-Path $tmpDir)) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Info "done. The tunnel is running and dialing $RelayUrl."
Write-Info "logs:   $LogPath"
Write-Info "status: Get-Service $ServiceName"
exit 0
