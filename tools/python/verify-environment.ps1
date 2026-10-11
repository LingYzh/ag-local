[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetDirectory,

    [switch]$CreateWheelhouse,

    [string]$WheelhouseDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PythonVersion = '3.14.6'
$RuntimeFileName = 'python-3.14.6-amd64.zip'
$RuntimeUrl = 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.zip'
$RuntimeManifestUrl = 'https://www.python.org/ftp/python/3.14.6/windows-3.14.6.json'
$RuntimeSha256 = '75afa83f93b284d19040e24bc440ab741c09582c0d5310504d607a4e08c3dbaf'
$PipVersion = '26.1.2'
$PipWheelFileName = 'pip-26.1.2-py3-none-any.whl'
$PipWheelSha256 = '382ff9f685ee3bc25864f820aa50505825f10f5458ffff07e30a6d96e5715cab'
$ExpectedLockedPackageCount = 12

function Get-FileSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Read-LockEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LockPath
    )

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $entryPattern = '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<version>[A-Za-z0-9][A-Za-z0-9.+_-]*) --hash=sha256:(?<sha256>[a-f0-9]{64})$'

    foreach ($rawLine in [System.IO.File]::ReadAllLines($LockPath)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) {
            continue
        }

        $matchResult = [regex]::Match($line, $entryPattern)
        if (-not $matchResult.Success) {
            throw ('Lock entry is not an exact version pin with one SHA-256: {0}' -f $line)
        }

        $packageName = ($matchResult.Groups['name'].Value -replace '[-_.]+', '-').ToLowerInvariant()
        $entries.Add([PSCustomObject]@{
            Name = $packageName
            Version = $matchResult.Groups['version'].Value
            Sha256 = $matchResult.Groups['sha256'].Value
        })
    }

    if ($entries.Count -ne $ExpectedLockedPackageCount) {
        throw ('Expected {0} locked distributions, found {1}.' -f $ExpectedLockedPackageCount, $entries.Count)
    }

    return $entries.ToArray()
}

function Test-Wheelhouse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [Parameter(Mandatory = $true)]
        [object[]]$LockEntries
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw ('Wheelhouse directory does not exist: {0}' -f $Directory)
    }

    $wheelhousePath = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $allFiles = @(Get-ChildItem -LiteralPath $wheelhousePath -File -Recurse)
    $topLevelFiles = @(Get-ChildItem -LiteralPath $wheelhousePath -File)
    if ($allFiles.Count -ne $topLevelFiles.Count) {
        throw 'Wheelhouse must contain only top-level wheel files.'
    }
    if ($topLevelFiles.Count -ne $LockEntries.Count) {
        throw ('Wheelhouse must contain exactly {0} files.' -f $LockEntries.Count)
    }

    $hashToName = @{}
    foreach ($entry in $LockEntries) {
        if ($hashToName.ContainsKey($entry.Sha256)) {
            throw ('Duplicate package hash in lock: {0}' -f $entry.Sha256)
        }
        $hashToName[$entry.Sha256] = $entry.Name
    }

    $seen = @{}
    foreach ($wheelFile in $topLevelFiles) {
        if ($wheelFile.Extension.ToLowerInvariant() -ne '.whl') {
            throw ('Wheelhouse contains a non-wheel file: {0}' -f $wheelFile.Name)
        }

        $wheelSha256 = Get-FileSha256 -LiteralPath $wheelFile.FullName
        if (-not $hashToName.ContainsKey($wheelSha256)) {
            throw ('Wheel hash is not present in the dependency lock: {0}' -f $wheelFile.Name)
        }

        $packageName = $hashToName[$wheelSha256]
        if ($seen.ContainsKey($packageName)) {
            throw ('Wheelhouse contains more than one wheel for {0}.' -f $packageName)
        }

        $seen[$packageName] = [ordered]@{
            name = $packageName
            filename = $wheelFile.Name
            sha256 = $wheelSha256
        }
    }

    if ($seen.Count -ne $LockEntries.Count) {
        throw 'Wheelhouse does not contain one verified wheel for every locked distribution.'
    }

    $manifest = @()
    foreach ($entry in $LockEntries) {
        $manifest += $seen[$entry.Name]
    }
    return $manifest
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$NativeArguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    & $Executable @NativeArguments
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        throw ('{0} failed with exit code {1}.' -f $Operation, $nativeExitCode)
    }
}

function Get-ExecutionSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$InstallerPath,

        [Parameter(Mandatory = $true)]
        [string]$EnvironmentTestsDirectory
    )

    if (-not (Test-Path -LiteralPath $EnvironmentTestsDirectory -PathType Container)) {
        throw 'Python environment tests directory is missing.'
    }

    $repositoryPrefix = $RepositoryRoot + '\'
    $sourcePaths = New-Object 'System.Collections.Generic.List[string]'
    $sourcePaths.Add((Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path)
    $testSources = @(Get-ChildItem -LiteralPath $EnvironmentTestsDirectory -Filter '*.py' -File -Recurse |
        Sort-Object -Property FullName)
    if ($testSources.Count -eq 0) {
        throw 'Python environment tests directory contains no Python source files.'
    }
    foreach ($testSource in $testSources) {
        $sourcePaths.Add($testSource.FullName)
    }

    $snapshot = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sourcePath in $sourcePaths) {
        $resolvedPath = (Resolve-Path -LiteralPath $sourcePath -ErrorAction Stop).Path
        if (-not $resolvedPath.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Execution source is outside the repository root.'
        }

        $relativePath = $resolvedPath.Substring($repositoryPrefix.Length).Replace('\', '/')
        $snapshot.Add([PSCustomObject]@{
            Path = $relativePath
            FullPath = $resolvedPath
            Sha256 = Get-FileSha256 -LiteralPath $resolvedPath
        })
    }

    return $snapshot.ToArray()
}

try {
    if ($CreateWheelhouse -and -not [string]::IsNullOrWhiteSpace($WheelhouseDirectory)) {
        throw 'Use either -CreateWheelhouse or -WheelhouseDirectory, not both.'
    }

    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
    $lockPath = Join-Path $repoRoot 'tools\python\requirements-win-cp314-x64.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw ('Dependency lock is missing: {0}' -f $lockPath)
    }

    $lockEntries = @(Read-LockEntries -LockPath $lockPath)
    $lockSha256 = Get-FileSha256 -LiteralPath $lockPath
    $environmentTestDirectory = Join-Path $repoRoot 'tests\python_environment'
    $executionSourceSnapshot = @(Get-ExecutionSourceSnapshot `
        -RepositoryRoot $repoRoot `
        -InstallerPath $PSCommandPath `
        -EnvironmentTestsDirectory $environmentTestDirectory)

    $preverifiedWheelhouse = @()
    if (-not $CreateWheelhouse -and -not [string]::IsNullOrWhiteSpace($WheelhouseDirectory)) {
        $preverifiedWheelhouse = @(Test-Wheelhouse -Directory $WheelhouseDirectory -LockEntries $lockEntries)
    }

    $targetPath = [System.IO.Path]::GetFullPath($TargetDirectory)
    $volumeRoot = [System.IO.Path]::GetPathRoot($targetPath)
    if ($targetPath -eq $volumeRoot) {
        throw 'Target directory cannot be a drive root.'
    }
    if (Test-Path -LiteralPath $targetPath) {
        throw ('Target directory already exists; choose a new path: {0}' -f $targetPath)
    }

    $targetParent = [System.IO.Directory]::GetParent($targetPath)
    if ($null -eq $targetParent) {
        throw 'Target directory must have a parent directory.'
    }
    if (-not (Test-Path -LiteralPath $targetParent.FullName -PathType Container)) {
        New-Item -ItemType Directory -Path $targetParent.FullName -Force -ErrorAction Stop | Out-Null
    }
    New-Item -ItemType Directory -Path $targetPath -ErrorAction Stop | Out-Null

    $archivePath = Join-Path $targetPath $RuntimeFileName
    Invoke-WebRequest -Uri $RuntimeUrl -OutFile $archivePath -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
    $actualRuntimeSha256 = Get-FileSha256 -LiteralPath $archivePath
    if ($actualRuntimeSha256 -ne $RuntimeSha256) {
        throw ('Python runtime ZIP SHA-256 mismatch: {0}' -f $actualRuntimeSha256)
    }

    $runtimeDirectory = Join-Path $targetPath 'runtime'
    New-Item -ItemType Directory -Path $runtimeDirectory -ErrorAction Stop | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $runtimeDirectory -ErrorAction Stop

    $runtimePython = Join-Path $runtimeDirectory 'python.exe'
    if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
        throw 'The verified runtime archive did not contain runtime/python.exe.'
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $runtimeProbePath = Join-Path $targetPath 'runtime-probe.py'
    $runtimeProbeCode = @'
import json
import platform
import struct
import sys
import sysconfig

print(json.dumps({
    "version": ".".join(map(str, sys.version_info[:3])),
    "implementation": platform.python_implementation(),
    "machine": platform.machine().upper(),
    "platform": sysconfig.get_platform(),
    "bits": struct.calcsize("P") * 8,
    "gil_disabled": sysconfig.get_config_var("Py_GIL_DISABLED"),
    "isolated": sys.flags.isolated,
}))
'@
    [System.IO.File]::WriteAllText($runtimeProbePath, $runtimeProbeCode, $utf8NoBom)
    $runtimeProbeLines = & $runtimePython -I -B $runtimeProbePath
    $runtimeProbeExitCode = $LASTEXITCODE
    if ($runtimeProbeExitCode -ne 0) {
        throw ('Runtime identity check failed with exit code {0}.' -f $runtimeProbeExitCode)
    }
    $runtimeProbeText = $runtimeProbeLines -join [System.Environment]::NewLine
    $runtimeProbe = $runtimeProbeText | ConvertFrom-Json -ErrorAction Stop

    if ($runtimeProbe.version -ne $PythonVersion -or
        $runtimeProbe.implementation -ne 'CPython' -or
        $runtimeProbe.machine -ne 'AMD64' -or
        $runtimeProbe.platform -ne 'win-amd64' -or
        $runtimeProbe.bits -ne 64 -or
        $runtimeProbe.gil_disabled -ne 0 -or
        $runtimeProbe.isolated -ne 1) {
        throw 'Runtime identity did not match CPython 3.14.6, Windows x64, GIL-enabled, isolated mode.'
    }

    $pipWheelPath = Join-Path $runtimeDirectory ('Lib\ensurepip\_bundled\' + $PipWheelFileName)
    if (-not (Test-Path -LiteralPath $pipWheelPath -PathType Leaf)) {
        throw ('Bundled pip bootstrap wheel is missing: {0}' -f $PipWheelFileName)
    }
    $actualPipWheelSha256 = Get-FileSha256 -LiteralPath $pipWheelPath
    if ($actualPipWheelSha256 -ne $PipWheelSha256) {
        throw ('Bundled pip wheel SHA-256 mismatch: {0}' -f $actualPipWheelSha256)
    }

    $venvDirectory = Join-Path $targetPath 'venv'
    Invoke-CheckedNative -Executable $runtimePython -NativeArguments @('-I', '-B', '-m', 'venv', $venvDirectory) -Operation 'Virtual environment creation'

    $venvPython = Join-Path $venvDirectory 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        throw 'Virtual environment did not contain venv/Scripts/python.exe.'
    }

    $pipVersionLines = & $venvPython -I -B -m pip --version
    $pipVersionExitCode = $LASTEXITCODE
    if ($pipVersionExitCode -ne 0) {
        throw ('pip version check failed with exit code {0}.' -f $pipVersionExitCode)
    }
    $pipVersionText = $pipVersionLines -join [System.Environment]::NewLine
    if (-not $pipVersionText.StartsWith(('pip {0} ' -f $PipVersion), [System.StringComparison]::Ordinal)) {
        throw ('Virtual environment pip did not match the bundled version {0}.' -f $PipVersion)
    }

    $wheelhousePath = $null
    $wheelhouseMode = 'pypi-online'
    $wheelhouseManifest = @()
    if ($CreateWheelhouse) {
        $wheelhousePath = Join-Path $targetPath 'wheelhouse'
        New-Item -ItemType Directory -Path $wheelhousePath -ErrorAction Stop | Out-Null

        $downloadArguments = @(
            '-I', '-B', '-m', 'pip',
            '--isolated', '--disable-pip-version-check', '--no-input', '--no-cache-dir',
            'download',
            '--require-hashes', '--only-binary=:all:',
            '--index-url', 'https://pypi.org/simple',
            '--dest', $wheelhousePath,
            '-r', $lockPath
        )
        Invoke-CheckedNative -Executable $venvPython -NativeArguments $downloadArguments -Operation 'Locked wheel download'
        $wheelhouseManifest = @(Test-Wheelhouse -Directory $wheelhousePath -LockEntries $lockEntries)
        $wheelhouseMode = 'generated-and-verified'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($WheelhouseDirectory)) {
        $wheelhousePath = (Resolve-Path -LiteralPath $WheelhouseDirectory -ErrorAction Stop).Path
        $wheelhouseManifest = $preverifiedWheelhouse
        $wheelhouseMode = 'existing-verified-wheelhouse'
    }

    $installArguments = @(
        '-I', '-B', '-m', 'pip',
        '--isolated', '--disable-pip-version-check', '--no-input', '--no-cache-dir',
        'install',
        '--require-hashes', '--only-binary=:all:'
    )
    if ($null -ne $wheelhousePath) {
        $installArguments += @('--no-index', '--find-links', $wheelhousePath)
    }
    else {
        $installArguments += @('--index-url', 'https://pypi.org/simple')
    }
    $installArguments += @('-r', $lockPath)
    Invoke-CheckedNative -Executable $venvPython -NativeArguments $installArguments -Operation 'Locked dependency installation'

    $pipCheckArguments = @('-I', '-B', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'check')
    Invoke-CheckedNative -Executable $venvPython -NativeArguments $pipCheckArguments -Operation 'pip check'

    $venvProbePath = Join-Path $targetPath 'venv-probe.py'
    $venvProbeCode = @'
import importlib.metadata
import json
import platform
import re
import site
import struct
import sys
import sysconfig

import UnityPy
import lz4.block

installed = {
    re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower(): distribution.version
    for distribution in importlib.metadata.distributions()
    if distribution.metadata.get("Name")
}
print(json.dumps({
    "version": ".".join(map(str, sys.version_info[:3])),
    "implementation": platform.python_implementation(),
    "machine": platform.machine().upper(),
    "platform": sysconfig.get_platform(),
    "bits": struct.calcsize("P") * 8,
    "gil_disabled": sysconfig.get_config_var("Py_GIL_DISABLED"),
    "isolated": sys.flags.isolated,
    "ignore_environment": sys.flags.ignore_environment,
    "no_user_site": sys.flags.no_user_site,
    "user_site_enabled": site.ENABLE_USER_SITE,
    "venv": sys.prefix != sys.base_prefix,
    "pip_version": importlib.metadata.version("pip"),
    "unitypy_version": importlib.metadata.version("UnityPy"),
    "lz4_version": importlib.metadata.version("lz4"),
    "installed": installed,
}))
'@
    [System.IO.File]::WriteAllText($venvProbePath, $venvProbeCode, $utf8NoBom)
    $venvProbeLines = & $venvPython -I -B $venvProbePath
    $venvProbeExitCode = $LASTEXITCODE
    if ($venvProbeExitCode -ne 0) {
        throw ('Installed environment import check failed with exit code {0}.' -f $venvProbeExitCode)
    }
    $venvProbeText = $venvProbeLines -join [System.Environment]::NewLine
    $venvProbe = $venvProbeText | ConvertFrom-Json -ErrorAction Stop

    if ($venvProbe.version -ne $PythonVersion -or
        $venvProbe.implementation -ne 'CPython' -or
        $venvProbe.machine -ne 'AMD64' -or
        $venvProbe.platform -ne 'win-amd64' -or
        $venvProbe.bits -ne 64 -or
        $venvProbe.gil_disabled -ne 0 -or
        $venvProbe.isolated -ne 1 -or
        $venvProbe.ignore_environment -ne 1 -or
        $venvProbe.no_user_site -ne 1 -or
        $venvProbe.user_site_enabled -ne $false -or
        $venvProbe.venv -ne $true -or
        $venvProbe.pip_version -ne $PipVersion -or
        $venvProbe.unitypy_version -ne '1.25.2' -or
        $venvProbe.lz4_version -ne '4.4.5') {
        throw 'Installed environment identity, isolation, or import check failed.'
    }

    foreach ($entry in $lockEntries) {
        $installedProperty = $venvProbe.installed.PSObject.Properties[$entry.Name]
        if ($null -eq $installedProperty -or $installedProperty.Value -ne $entry.Version) {
            throw ('Installed distribution does not match lock: {0}=={1}' -f $entry.Name, $entry.Version)
        }
    }
    if (@($venvProbe.installed.PSObject.Properties).Count -ne ($lockEntries.Count + 1)) {
        throw 'The virtual environment contains distributions outside the dependency lock and bundled pip.'
    }

    $testArguments = @(
        '-I', '-B', '-m', 'unittest', 'discover',
        '-s', $environmentTestDirectory,
        '-p', 'test_*.py',
        '-v'
    )
    Invoke-CheckedNative -Executable $venvPython -NativeArguments $testArguments -Operation 'Python environment contract tests'

    $currentExecutionSourceSnapshot = @(Get-ExecutionSourceSnapshot `
        -RepositoryRoot $repoRoot `
        -InstallerPath $PSCommandPath `
        -EnvironmentTestsDirectory $environmentTestDirectory)
    if ($currentExecutionSourceSnapshot.Count -ne $executionSourceSnapshot.Count) {
        throw 'Python environment installer or test source set changed during verification.'
    }
    for ($sourceIndex = 0; $sourceIndex -lt $executionSourceSnapshot.Count; $sourceIndex++) {
        if ($currentExecutionSourceSnapshot[$sourceIndex].Path -ne $executionSourceSnapshot[$sourceIndex].Path -or
            $currentExecutionSourceSnapshot[$sourceIndex].Sha256 -ne $executionSourceSnapshot[$sourceIndex].Sha256) {
            throw ('Python environment installer or test source changed during verification: {0}' -f $executionSourceSnapshot[$sourceIndex].Path)
        }
    }

    $lockedPackageReport = @()
    foreach ($entry in $lockEntries) {
        $lockedPackageReport += [ordered]@{
            name = $entry.Name
            version = $entry.Version
            wheel_sha256 = $entry.Sha256
            installed_version = $venvProbe.installed.PSObject.Properties[$entry.Name].Value
        }
    }

    $executionSourcesReport = @()
    foreach ($source in $executionSourceSnapshot) {
        $executionSourcesReport += [ordered]@{
            path = $source.Path
            sha256 = $source.Sha256
        }
    }

    $runtimePythonSha256 = Get-FileSha256 -LiteralPath $runtimePython
    $venvPythonSha256 = Get-FileSha256 -LiteralPath $venvPython
    $report = [ordered]@{
        format_version = 1
        generated_utc = [System.DateTime]::UtcNow.ToString('o')
        python_distribution = [ordered]@{
            filename = $RuntimeFileName
            url = $RuntimeUrl
            official_manifest_url = $RuntimeManifestUrl
            expected_sha256 = $RuntimeSha256
            actual_sha256 = $actualRuntimeSha256
            implementation = $runtimeProbe.implementation
            version = $runtimeProbe.version
            architecture = $runtimeProbe.machine
            sysconfig_platform = $runtimeProbe.platform
            pointer_bits = $runtimeProbe.bits
            gil_disabled = $runtimeProbe.gil_disabled
            runtime_executable = 'runtime/python.exe'
            runtime_executable_sha256 = $runtimePythonSha256
            venv_executable = 'venv/Scripts/python.exe'
            venv_executable_sha256 = $venvPythonSha256
        }
        pip_bootstrap = [ordered]@{
            source = 'ensurepip wheel bundled in the SHA-verified Python ZIP'
            version = $PipVersion
            filename = $PipWheelFileName
            sha256 = $actualPipWheelSha256
        }
        dependency_lock = [ordered]@{
            path = 'tools/python/requirements-win-cp314-x64.lock'
            sha256 = $lockSha256
            packages = $lockedPackageReport
        }
        execution_sources = $executionSourcesReport
        validation = [ordered]@{
            isolated_python = $true
            pip_check = 'passed'
            imports = 'UnityPy 1.25.2 and lz4 4.4.5 passed'
            environment_contract_tests = 'passed'
            wheelhouse_mode = $wheelhouseMode
            wheelhouse = $wheelhouseManifest
        }
        privacy = 'Repository-relative paths and allowlisted environment metadata only.'
    }

    $reportPath = Join-Path $targetPath 'environment-report.json'
    $reportJson = $report | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($reportPath, $reportJson + [System.Environment]::NewLine, $utf8NoBom)

    Write-Host ('Environment verification passed. Report: {0}' -f $reportPath)
}
catch {
    Write-Error -Message ('Environment verification failed: {0}' -f $_.Exception.Message) -ErrorAction Continue
    throw
}
