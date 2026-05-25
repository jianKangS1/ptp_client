# Shared: resolve config/ptp-acr-client.json -> python -m ptp_client.ptp argument list.

function Read-PtpAcrClientConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  # Allow // line comments and /* */ block comments (JSONC) in config for field docs.
    $raw = [regex]::Replace($raw, '/\*[\s\S]*?\*/', '')
    $lines = $raw -split "`r?`n"
    $clean = ($lines | ForEach-Object {
            $line = $_
            if ($line -match '^\s*//') { return $null }
            if ($line -match '^(.*?)\s//.*$') { return $matches[1] }
            return $line
        } | Where-Object { $_ -ne $null }) -join "`n"
    return $clean | ConvertFrom-Json
}

function Get-WslEth0IPv4 {
    $out = & wsl.exe -e bash -lc "ip -4 -br addr show eth0 2>/dev/null" 2>$null
    if (-not $out) { return $null }
    $m = [regex]::Match([string]$out, '\b(\d{1,3}(?:\.\d{1,3}){3})/')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Add-G82752CliArgs {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Cfg,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Args
    )
    $ann = 0
    if ($null -ne $Cfg.announceLogPeriod) { $ann = [int]$Cfg.announceLogPeriod }
    $sync = 0
    if ($null -ne $Cfg.syncLogPeriod) { $sync = [int]$Cfg.syncLogPeriod }
    $dur = 300
    if ($null -ne $Cfg.durationSec) { $dur = [int]$Cfg.durationSec }

    [void]$Args.Add("--announce-log")
    [void]$Args.Add([string]$ann)
    [void]$Args.Add("--sync-log")
    [void]$Args.Add([string]$sync)
    [void]$Args.Add("--duration")
    [void]$Args.Add([string]$dur)
    $meas = 0
    if ($null -ne $Cfg.measureDurationSec) { $meas = [int]$Cfg.measureDurationSec }
    [void]$Args.Add("--measure-duration")
    [void]$Args.Add([string]$meas)
}

function Add-DelayRequestCliArgs {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Cfg,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Args
    )
    if ($null -eq $Cfg.delayRequest) { return }
    $dr = $Cfg.delayRequest
    if ($dr.clockIdentity) {
        [void]$Args.Add("--delay-req-clock-identity")
        [void]$Args.Add([string]$dr.clockIdentity)
    }
    if ($null -ne $dr.portNumber) {
        [void]$Args.Add("--delay-req-port-number")
        [void]$Args.Add([string][int]$dr.portNumber)
    }
    if ($null -ne $dr.flags) {
        [void]$Args.Add("--delay-req-flags")
        [void]$Args.Add(('0x{0:X}' -f [int]$dr.flags))
    }
    if ($null -ne $dr.correctionFieldNs) {
        [void]$Args.Add("--delay-req-correction-ns")
        [void]$Args.Add([string]$dr.correctionFieldNs)
    }
    if ($null -ne $dr.requestIntervalSec) {
        [void]$Args.Add("--delay-req-interval")
        [void]$Args.Add([string]$dr.requestIntervalSec)
    }
    if ($null -ne $dr.originTimestamp) {
        if ($null -ne $dr.originTimestamp.seconds) {
            [void]$Args.Add("--delay-req-origin-sec")
            [void]$Args.Add([string]$dr.originTimestamp.seconds)
        }
        if ($null -ne $dr.originTimestamp.nanoseconds) {
            [void]$Args.Add("--delay-req-origin-ns")
            [void]$Args.Add([string]$dr.originTimestamp.nanoseconds)
        }
    }
}

function Resolve-PtpAcrClientLaunch {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Cfg
    )

    $master = [string]$Cfg.master
    if ([string]::IsNullOrWhiteSpace($master)) {
        $master = Get-WslEth0IPv4
        if (-not $master) {
            throw "config master is empty and WSL eth0 IPv4 could not be resolved"
        }
        $masterSource = "wsl-eth0"
    } else {
        $masterSource = "config"
    }

    $profile = "g8275.2"
    if ($null -ne $Cfg.profile -and -not [string]::IsNullOrWhiteSpace([string]$Cfg.profile)) {
        $profile = [string]$Cfg.profile
    }
    $profileKey = $profile.ToLowerInvariant().Replace(".", "").Replace("-", "")

    $domain = if ($profileKey -match "82751") { 24 } else { 44 }
    if ($null -ne $Cfg.domain) { $domain = [int]$Cfg.domain }

    $transport = "unicast"
    if ($null -ne $Cfg.transport -and -not [string]::IsNullOrWhiteSpace([string]$Cfg.transport)) {
        $transport = [string]$Cfg.transport
    } elseif ($profileKey -match "82751") {
        $transport = "multicast"
    }

    $mode = [string]$Cfg.mode
    if ([string]::IsNullOrWhiteSpace($mode)) {
        $mode = if ($profileKey -match "82752") { "g8275-acr" } else { "estimate" }
    }
    $modeKey = $mode.ToLowerInvariant()

    if ($modeKey -eq "g8275-negotiate" -and $profileKey -match "82751") {
        Write-Warning "G.8275.1 uses multicast; g8275-negotiate is G.8275.2 unicast only."
    }

    switch ($modeKey) {
        "estimate" {
            $syncT = if ($null -ne $Cfg.syncTimeout) { [double]$Cfg.syncTimeout } else { 8.0 }
            $delayT = if ($null -ne $Cfg.delayTimeout) { [double]$Cfg.delayTimeout } else { 8.0 }
            $tailArgs = [System.Collections.Generic.List[string]]@(
                "estimate", [string]$master,
                "--domain", [string]$domain,
                "--sync-timeout", [string]$syncT,
                "--delay-timeout", [string]$delayT
            )
            Add-DelayRequestCliArgs -Cfg $Cfg -Args $tailArgs
        }
        "delay" {
            $one = if ($null -ne $Cfg.delayTimeoutSingle) { [double]$Cfg.delayTimeoutSingle } else { 8.0 }
            $tailArgs = [System.Collections.Generic.List[string]]@(
                "delay", [string]$master,
                "--domain", [string]$domain,
                "--timeout", [string]$one
            )
            Add-DelayRequestCliArgs -Cfg $Cfg -Args $tailArgs
        }
        "g8275-negotiate" {
            $tailArgs = [System.Collections.Generic.List[string]]@(
                "g8275-negotiate", [string]$master,
                "--domain", [string]$domain
            )
            Add-G82752CliArgs -Cfg $Cfg -Args $tailArgs
        }
        "g8275-acr" {
            $syncT = if ($null -ne $Cfg.syncTimeout) { [double]$Cfg.syncTimeout } else { 8.0 }
            $delayT = if ($null -ne $Cfg.delayTimeout) { [double]$Cfg.delayTimeout } else { 8.0 }
            $tailArgs = [System.Collections.Generic.List[string]]@(
                "g8275-acr", [string]$master,
                "--domain", [string]$domain,
                "--sync-timeout", [string]$syncT,
                "--delay-timeout", [string]$delayT
            )
            Add-G82752CliArgs -Cfg $Cfg -Args $tailArgs
            Add-DelayRequestCliArgs -Cfg $Cfg -Args $tailArgs
        }
        default {
            throw "unsupported mode: $mode (estimate | delay | g8275-negotiate | g8275-acr)"
        }
    }

    $pyArgs = @("-u", "-m", "ptp_client.ptp") + [string[]]$tailArgs

    if ($modeKey -in @("estimate", "delay")) {
        $pyArgs += @("--transport", $transport)
    }

    $bindStr = if ($null -ne $Cfg.bind) { [string]$Cfg.bind } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($bindStr)) {
        $bindPort = if ($null -ne $Cfg.bindPort) { [int]$Cfg.bindPort } else { 0 }
        $pyArgs += @("--bind", $bindStr, "--bind-port", ([string]$bindPort))
    }

    if ($Cfg.extraArgs -and $Cfg.extraArgs.Count -gt 0) {
        foreach ($a in $Cfg.extraArgs) {
            $pyArgs += [string]$a
        }
    }

    return [PSCustomObject]@{
        Master       = $master
        MasterSource = $masterSource
        Profile      = $profile
        Domain       = $domain
        Transport    = $transport
        Mode         = $mode
        Bind         = $(if ([string]::IsNullOrWhiteSpace($bindStr)) { $null } else { $bindStr })
        BindPort     = $(if ([string]::IsNullOrWhiteSpace($bindStr)) { $null } else { if ($null -ne $Cfg.bindPort) { [int]$Cfg.bindPort } else { 0 } })
        PyArgs       = $pyArgs
    }
}
