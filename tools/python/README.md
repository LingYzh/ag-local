# Python recovery tool environment

## Scope and verified target

Only the static protocol recovery tool has third-party Python dependencies. Its direct inputs are UnityPy 1.25.2, used for Unity's common-string table, and lz4 4.4.5, used by the LZ4 branch. The controlled service entry, network framing, evidence tools, and validation tools are kept standard-library-only. Environment tests scan those source boundaries so an accidental third-party import is visible.

The verified combination is Windows x64, standard GIL-enabled CPython 3.14.6, with the win_amd64 wheel target. Other Python versions, architectures, operating systems, and free-threaded builds are unverified and are not claimed as supported. This is the pinned environment associated with the existing static extraction evidence; it is not a claim that 3.14.6 is the newest Python release.

## Runtime and bootstrap provenance

The independent runtime comes from the official Python 3.14.6 Windows x64 archive:

| Item | Value |
| --- | --- |
| Official distribution | https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.zip |
| Official Windows release manifest | https://www.python.org/ftp/python/3.14.6/windows-3.14.6.json |
| Manifest identity | pythoncore-3.14-64 |
| Runtime ZIP SHA-256 | 75afa83f93b284d19040e24bc440ab741c09582c0d5310504d607a4e08c3dbaf |
| Bundled ensurepip version | pip 26.1.2 |
| Bundled pip wheel SHA-256 | 382ff9f685ee3bc25864f820aa50505825f10f5458ffff07e30a6d96e5715cab |

The verification script checks the archive hash before extraction, then verifies CPython version, AMD64 architecture, win-amd64 platform, 64-bit pointers, and the GIL-enabled build. It creates a new venv from that extracted runtime. The exact pip version comes from the pip wheel embedded in the hash-verified runtime archive; the script checks its wheel hash and does not upgrade pip from the network.

Each run writes environment-report.json under its new target. The report records the runtime ZIP SHA-256, actual runtime and venv python.exe hashes, pip version and bootstrap-wheel hash, dependency-lock SHA-256, installed package versions, architecture, isolation checks, and validation results. It also binds the installer and every Python source under tests/python_environment to fixed repository-relative paths and SHA-256 values, and fails if those sources change during verification. It omits absolute user paths and environment-variable values.

## Dependency lock and wheel availability

The direct input is requirements.in. The platform-specific lock is requirements-win-cp314-x64.lock; its SHA-256 is d38f3b944957676e00b57a817aded2d9009b88c93ef6f9b4998b60b0bc3919cb. It contains exact versions and one SHA-256 for each of 12 distributions: the two direct inputs and their resolved transitive dependencies. The lock permits only binary wheels for this target; it is not a cross-platform lock.

On 2026-10-11, each locked file hash was matched against the corresponding PyPI release JSON metadata. pip 26.1.2 also resolved and downloaded all 12 wheels for the verified CPython 3.14.6 win_amd64 runtime using binary-only resolution. The selected wheel files were:

| Distribution | Version | Selected wheel |
| --- | --- | --- |
| archspec | 0.2.6 | archspec-0.2.6-py3-none-any.whl |
| astc-encoder-py | 0.1.12 | astc_encoder_py-0.1.12-cp37-abi3-win_amd64.whl |
| attrs | 26.1.0 | attrs-26.1.0-py3-none-any.whl |
| brotli | 1.2.0 | brotli-1.2.0-cp314-cp314-win_amd64.whl |
| etcpak | 0.9.15 | etcpak-0.9.15-cp37-abi3-win_amd64.whl |
| fmod-toolkit | 0.1.3 | fmod_toolkit-0.1.3-cp38-abi3.abi3t-win_amd64.whl |
| fsspec | 2026.9.0 | fsspec-2026.9.0-py3-none-any.whl |
| lz4 | 4.4.5 | lz4-4.4.5-cp314-cp314-win_amd64.whl |
| pillow | 12.3.0 | pillow-12.3.0-cp314-cp314-win_amd64.whl |
| pyfmodex | 0.7.2 | pyfmodex-0.7.2-py3-none-any.whl |
| texture2ddecoder | 1.0.6 | texture2ddecoder-1.0.6-cp311-abi3-win_amd64.whl |
| UnityPy | 1.25.2 | unitypy-1.25.2-cp314-cp314-win_amd64.whl |

The SHA-256 for each selected wheel is in the lock. The verification script uses --require-hashes and --only-binary=:all:. It also supports an optional wheelhouse: -CreateWheelhouse downloads all locked wheels into the new target, checks the exact file count and every hash, then installs from that directory with --no-index. -WheelhouseDirectory validates an existing wheelhouse the same way before offline installation. A wheelhouse must contain exactly the locked wheels at its top level.

## Reproduce from a clean checkout

Run these commands from the checkout root in Windows PowerShell 5.1. The script is ASCII-only and is invoked through the system PowerShell path. The target must be new; the script fails if it already exists and leaves partial output for inspection if a step fails.

~~~powershell
$target = Join-Path (Get-Location).Path ('qa\python-environment\h02-' + [guid]::NewGuid().ToString('N'))
$powerShell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $powerShell51 -NoProfile -EP Bypass -File .\tools\python\verify-environment.ps1 -TargetDirectory $target -CreateWheelhouse
if ($LASTEXITCODE -ne 0) { throw 'Python environment verification failed.' }
$python = Join-Path $target 'venv\Scripts\python.exe'
$report = Join-Path $target 'synthetic-tests.json'
& $python -I -B .\tools\validation\run_python_tests.py --output $report
if ($LASTEXITCODE -ne 0) { throw 'Synthetic Python suites failed.' }
~~~

verify-environment.ps1 downloads and verifies the official runtime, writes generic ASCII runtime probes as `.py` files to avoid native `-c` quoting differences in Windows PowerShell 5.1, builds the fresh runtime/venv, installs the lock with hash checking, runs pip check, verifies UnityPy and lz4 imports, and runs the tests in tests/python_environment. The repository runner then executes the full synthetic suite set and writes a source-bound JSON report. The local qa/ directory is ignored by Git; runtime files, environments, wheels, extracted schemas, and reports must remain there or in an equivalent external temporary directory.

## Optional local extraction comparison

A real schema rebuild requires the matching user-local scripts bundle. It is an explicit input and is never copied into the repository. For the recorded Windows client, first verify the bundle SHA-256, then use the isolated wrapper; it requires `-I` before inserting only its own checkout root and calling the existing module CLI.

~~~powershell
$sourceRoot = 'D:\AetherGazerStarter\AetherGazer'
$bundle = 'D:\AetherGazerStarter\AetherGazer\AetherGazer_Data\StreamingAssets\Windows\f\9\f9468cd00564c3c98e4f819210760be1.ys'
$bundleSha256 = 'd39fcc02eb38d4966d3732d9008d75cb41913194942a4800ad5a7585104a0019'
(Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash
$outputA = Join-Path $target 'extract-a'
$outputB = Join-Path $target 'extract-b'
& $python -I -B .\tools\python\run-static-extract.py --source-root $sourceRoot --bundle $bundle --sha256 $bundleSha256 --output-directory $outputA
if ($LASTEXITCODE -ne 0) { throw 'First static extraction failed.' }
& $python -I -B .\tools\python\run-static-extract.py --source-root $sourceRoot --bundle $bundle --sha256 $bundleSha256 --output-directory $outputB
if ($LASTEXITCODE -ne 0) { throw 'Second static extraction failed.' }
~~~

The expected bundle SHA-256 is d39fcc02eb38d4966d3732d9008d75cb41913194942a4800ad5a7585104a0019. Both output directories must be new. Compare schema.json, schema.sha256, and extraction-report.json between extract-a and extract-b. The expected schema SHA-256 for schema.json and schema.sha256 content is 917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0. The extraction report explicitly records runtime_test_performed=false and compatibility_admitted=false; this is static declaration recovery only and does not establish client compatibility.

No game, service, or protected client files are changed by this workflow. Do not add the runtime, venv, wheelhouse, or local extraction outputs to version control.
