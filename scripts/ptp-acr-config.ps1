# Shared: resolve config/ptp-acr-client.json -> python -m ptp_client.ptp argument list.

function Get-WslEth0IPv4 {
    $out = & wsl.exe -e bash -lc "ip -4 -br addr show eth0 2>/dev/null" 2>$null
    if (-not $out) { return $null }
    $m = [regex]::Match([string]$out, '\b(\d{1,3}(?:\.\d{1,3}){3})/')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
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
        $mode = if ($profileKey -match "82752") { "g8275-negotiate" } else { "estimate" }
    }
    $modeKey = $mode.ToLowerInvariant()

    if ($modeKey -eq "g8275-negotiate" -and $profileKey -match "82751") {
        Write-Warning "G.8275.1 uses multicast; g8275-negotiate is G.8275.2 unicast only."
    }

    switch ($modeKey) {
        "estimate" {
            $syncT = if ($null -ne $Cfg.syncTimeout) { [double]$Cfg.syncTimeout } else { 8.0 }
            $delayT = if ($null -ne $Cfg.delayTimeout) { [double]$Cfg.delayTimeout } else { 8.0 }
            $tailArgs = @(
                "estimate", [string]$master,
                "--domain", [string]$domain,
                "--sync-timeout", [string]$syncT,
                "--delay-timeout", [string]$delayT
            )
        }
        "delay" {
            $one = if ($null -ne $Cfg.delayTimeoutSingle) { [double]$Cfg.delayTimeoutSingle } else { 8.0 }
            $tailArgs = @(
                "delay", [string]$master,
                "--domain", [string]$domain,
                "--timeout", [string]$one
            )
        }
        "g8275-negotiate" {
            $tailArgs = @("g8275-negotiate", [string]$master, "--domain", [string]$domain)
        }
        default {
            throw "unsupported mode: $mode (estimate | delay | g8275-negotiate)"
        }
    }

    $pyArgs = @("-u", "-m", "ptp_client.ptp") + $tailArgs

    # g8275-negotiate subcommand has no --transport (always unicast)
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
