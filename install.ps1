Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process;

Write-Output "`n      _____        __                    _____  ___
      \_   \_ __  / _| ___  ___  ___  __/__   \/ __\
       / /\/ '_ \| |_ / _ \/ __|/ _ \/ __|/ /\/ _\
    /\/ /_ | | | |  _| (_) \__ \  __/ (__/ / / /
    \____/ |_| |_|_|  \___/|___/\___|\___\/  \/`n`n";

function Test-Administrator
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

# Check if the script is running as Administrator
if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.`nPlease run PowerShell as Administrator and try again.";
    Read-Host -Prompt 'Press Enter to exit'
    $ErrorActionPreference = "Stop";
    exit 1;
}else{
    Write-Output "InfosecTF`n";
}

# Set Variables
$ProxyPath = "";
# $ProxyID = "";
# $ProxyPW = "";
$ProxyBP = ""; # Bypass List, e.g. 'http://localhost,http://this.location/'
$ChocoPath = "C:\ProgramData\chocolatey\choco.exe";
$GitPath = "C:\Program Files\Git\bin\git.exe";
# $Home = "C:\Users\$($env:USERNAME)";

# Make New Directory
if(-not (Test-Path "$Home\Tools"))
{
    $null = New-Item -path "$Home\Tools" -ItemType "Directory" -Force;
}


# 
# Chocolatey Configuration
function ChocoCfgProxy
{
    if($ProxyPath)
    {
        Write-Output " - Choco Proxy: $ProxyPath";
        Start-Process -FilePath $ChocoPath -ArgumentList "config", "set", "--name", "proxy", "--value", $ProxyPath -Wait;
        # Start-Process -FilePath $ChocoPath -ArgumentList "config", "set", "--name", "proxyUser", "--value", $ProxyID -Wait;
        # Start-Process -FilePath $ChocoPath -ArgumentList "config", "set", "--name", "proxyPassword", "--value", $ProxyPW -Wait;
        if($ProxyBP)
        {
            Start-Process -FilePath $ChocoPath -ArgumentList "config", "set", "--name", "proxyBypassList", "--value", $ProxyBP -Wait;
        }
        Start-Process -FilePath $ChocoPath -ArgumentList "config", "set", "--name", "proxyBypassOnLocal", "--value", "true" -Wait;
    }else{
        Write-Output " - Choco Proxy: Nothing"; 
        # Start-Process -FilePath $ChocoPath -ArgumentList "config", "unset", "proxy" -Wait;
    }
}
#
# Chocolatey Installation
if(-not (Test-Path $ChocoPath))
{
    Write-Output " - Chocolatey Installation";
    $null = New-Item -Path "$Env:Temp" -Name "chocolatey-install.ps1" -ItemType "file" -Force -Value "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'));";
    Start-Process powershell.exe -ArgumentList "powershell", "-C", "'$Env:Temp\chocolatey-install.ps1'" -Wait;
    Remove-Item -Path "$Env:Temp\chocolatey-install.ps1" -Force;
    ChocoCfgProxy
}else{
    # Chocolatey Upgrade
    ChocoCfgProxy
    Write-Output " - Chocolatey Uprade";
    Start-Process -FilePath $ChocoPath -ArgumentList "upgrade", "-y", "chocolatey" -Wait;
}
# 
# Through Chocolatey
function ChocoIns($ChocoPkg)
{
    Write-Output " - Install: $ChocoPkg";
    Start-Process -FilePath $ChocoPath -ArgumentList "install", "-y", $ChocoPkg -Wait;
    # $null = Invoke-Expression -Command "$ChocoPath install -y $ChocoPkg";
}
# Choco Tools
ChocoIns choco-protocol-support
ChocoIns choco-cleaner
# Fonts
ChocoIns nerd-fonts-meslo
ChocoIns nerd-fonts-sourcecodepro
# Utilities
ChocoIns powertoys
ChocoIns openssl
ChocoIns gnupg
ChocoIns powershell-core
ChocoIns git
ChocoIns git-lfs
ChocoIns svn
ChocoIns starship
ChocoIns 7zip
ChocoIns gzip
ChocoIns bzip2
ChocoIns vlc
ChocoIns obs-studio
ChocoIns screentogif
ChocoIns rufus
ChocoIns curl
ChocoIns wget
ChocoIns vim
ChocoIns neovim
ChocoIns bat
ChocoIns jq
ChocoIns hub
ChocoIns gh
ChocoIns watchman
ChocoIns ghostscript.app
ChocoIns imagemagick.app
# Languages
ChocoIns gawk
ChocoIns llvm
ChocoIns rust
ChocoIns rust-analyzer
ChocoIns go
ChocoIns dep
ChocoIns strawberryperl
ChocoIns python311
ChocoIns ruby
ChocoIns lua
ChocoIns nvm
ChocoIns php
ChocoIns haskell-dev
ChocoIns openjdk
ChocoIns openjdk17
ChocoIns openjdk11
ChocoIns groovy
ChocoIns scala
ChocoIns clojure
ChocoIns erlang
ChocoIns elixir
ChocoIns r
ChocoIns rtools
ChocoIns julia
ChocoIns visualstudio2022community
# Build Tools
ChocoIns make
ChocoIns cmake
ChocoIns ccache
ChocoIns ant
ChocoIns maven
ChocoIns gradle
ChocoIns opencv
ChocoIns re2c
# Developer Tools
ChocoIns neovide
ChocoIns vscode
ChocoIns vscodium
ChocoIns atom
ChocoIns notepadplusplus
ChocoIns eclipse
ChocoIns intellijidea-community
ChocoIns androidstudio
ChocoIns hyper
ChocoIns alacritty
ChocoIns postman
ChocoIns httpie
ChocoIns httpie-desktop
ChocoIns sqlitebrowser
ChocoIns apache-httpd
ChocoIns tomcat
ChocoIns sqlite
ChocoIns sqlite.shell
ChocoIns sqlite.analyzer
ChocoIns mysql
ChocoIns postgresql
ChocoIns mongodb
# Virtualization Tools
ChocoIns docker-desktop
ChocoIns qemu
# OSINT Tools
ChocoIns nessus-agent
# Internet Tools
ChocoIns thunderbird
ChocoIns googlechrome
ChocoIns firefox
ChocoIns tor-browser
ChocoIns burp-suite-free-edition
ChocoIns zap
# Networking Tools
ChocoIns putty
ChocoIns winscp
ChocoIns vnc-connect
ChocoIns openvpn
ChocoIns wireshark
ChocoIns angryip
# Reversing Tools
ChocoIns hxd
ChocoIns radare2
ChocoIns cutter
ChocoIns ghidra
ChocoIns ilspy

# Git Configuration
if ($ProxyPath)
{
    Write-Output " - Git SSL Verify: false";
    $null = Invoke-Expression -Command "$GitPath http.sslVerify false"
    Write-Output " - Git Proxy: $ProxyPath";
    $null = Invoke-Expression -Command "$GitPath http.proxy $ProxyPath"
}else{
    # git config --global --unset http.proxy;
    # git config --global --unset http.sslVerify;
}
# 
# Through Git
function GitIns($RepoName, $GitRepo)
{
    Write-Output " - Git Clone: $RepoName";
    Start-Process -FilePath $GitPath -ArgumentList "clone", $GitRepo, "$Home\Tools\$RepoName" -Wait;
}
GitIns theharvester https://github.com/laramies/theHarvester
GitIns fierce-domain-scanner https://github.com/davidpepper/fierce-domain-scanner
GitIns cain https://github.com/xchwarze/Cain

# Through Download on Web
function WebDl($ToolName, $FileName, $WebUrl)
{
    Write-Output " - Web Download: $ToolName";
    $null = Invoke-Expression -Command "Invoke-WebRequest -Uri $WebUrl -OutFile '$Home\Downloads\$FileName'";
    if($ToolName)
    {
        $null = New-Item -path "$Home\Tools\$ToolName" -ItemType "Directory" -Force;
    }
}
WebDl proxify proxify.zip https://github.com/projectdiscovery/proxify/releases/download/v0.0.8/proxify_0.0.8_windows_amd64.zip
WebDl ffuf ffuf.zip https://github.com/ffuf/ffuf/releases/download/v1.5.0/ffuf_1.5.0_windows_amd64.zip
WebDl dalfox dalfox.tar.gz https://github.com/hahwul/dalfox/releases/download/v2.8.2/dalfox_2.8.2_windows_amd64.tar.gz
WebDl subfinder subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.5.5/subfinder_2.5.5_windows_amd64.zip
WebDl nuclei nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v2.8.8/nuclei_2.8.8_windows_amd64.zip
WebDl packetsender packetsender.exe https://github.com/dannagle/PacketSender/releases/download/v8.1.1/PacketSender_x64_v8.1.1.exe
WebDl john john.7z  https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.7z
WebDl x64dbg x64dbg.zip https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2023-01-25_11-53.zip
WebDl jadx jadx.exe https://github.com/skylot/jadx/releases/download/v1.4.5/jadx-gui-1.4.5-no-jre-win.exe
WebDl aircrack-ng aircrack-ng.zip https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip


# Finish Message
Wirte-Output "`nFinished!";
