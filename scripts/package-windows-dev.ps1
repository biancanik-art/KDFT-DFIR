<#
.SYNOPSIS
    Builds, smoke-checks, and packages a safe Windows developer distribution of KDFT.

.DESCRIPTION
    Automates the Windows developer package workflow for the KDFT workspace.
    Produces a new, uniquely timestamped package directory under dist/kdft-windows-dev-<timestamp>/
    without deleting, modifying, or overwriting prior packages.

    Packaged binaries:
      - kdft-desktop.exe : Desktop (Primary native case and evidence workflow)
      - kdft-ui.exe      : Workbench (Optional browser-assisted analysis UI)
      - kdft.exe         : CLI (Command-line forensic workflows)

    Packaged metadata & legal:
      - LICENSE          : Apache-2.0 License
      - NOTICE           : KDFT copyright and attribution notices
      - THIRD_PARTY_NOTICES : Third-party dependency notices
      - README.txt       : Clear component labeling, usage, and safety boundaries
      - manifest.json    : Machine-readable provenance and package manifest
      - SHA256SUMS.txt   : SHA-256 hashes of all packaged files

    Safety and Integrity Guarantees:
      - Uses native PowerShell and literal paths throughout.
      - Never performs recursive deletion; leaves all prior packages intact.
      - Fails closed on any formatting, test, build, copy, or hash error.
      - Strictly excludes case databases, evidence images, log files, credentials,
        staging/import directories, target debug files, and pre-existing release binaries.
      - Performs an automated post-staging blacklist audit before hash generation.
      - Discloses git commit and dirty working-tree state in both console and manifest.
      - Zero network access, code signing, or remote publishing.

.PARAMETER DryRun
    Runs non-destructive validation of prerequisites, git disclosure, paths, manifest schema,
    and packaging rules without running release compilation or writing distribution files.

.PARAMETER SkipFmt
    Skips the cargo fmt --check step.

.PARAMETER SkipTests
    Skips running smoke tests.

.PARAMETER SkipBuild
    Skips cargo build --release (requires target/release binaries to exist).

.PARAMETER Zip
    Creates a .zip archive of the packaged directory alongside the folder.

.PARAMETER DistRoot
    Custom parent directory for distribution packages (defaults to <repo_root>/dist).

.PARAMETER SmokeTestTargets
    Array of cargo test package targets to execute (defaults to desktop core, desktop, UI, and CLI).

.EXAMPLE
    .\scripts\package-windows-dev.ps1 -DryRun
    Runs non-destructive validation and reports status.

.EXAMPLE
    .\scripts\package-windows-dev.ps1
    Runs format check, smoke tests, builds release binaries, stages package, and computes hashes.

.EXAMPLE
    .\scripts\package-windows-dev.ps1 -Zip
    Runs full build and packaging workflow, plus creates a timestamped zip archive.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipFmt,
    [switch]$SkipTests,
    [switch]$SkipBuild,
    [switch]$Zip,
    [string]$DistRoot = "",
    [string]$ReleaseBinDir = "",
    [string[]]$SmokeTestTargets = @("kdft-desktop-core", "kdft-desktop", "kdft-ui", "kdft-cli")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# 1. Path Resolution and Workspace Validation
# -----------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..")).Path
$cargoTomlPath = Join-Path $repoRoot "Cargo.toml"

if (-not (Test-Path -LiteralPath $cargoTomlPath)) {
    throw "Safety failure: Cargo.toml not found at expected repository root: $repoRoot"
}

if ([string]::IsNullOrWhiteSpace($DistRoot)) {
    $finalDistRoot = Join-Path $repoRoot "dist"
} else {
    $finalDistRoot = if ([System.IO.Path]::IsPathRooted($DistRoot)) {
        [System.IO.Path]::GetFullPath($DistRoot)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $DistRoot))
    }
}

# -----------------------------------------------------------------------------
# 2. Blacklist and Exclusion Rules (Security & Boundary Defense)
# -----------------------------------------------------------------------------
# The package MUST NEVER contain:
#   - case DBs (*.sqlite, *.db, *.kdft.sqlite, etc.)
#   - evidence images (*.vhd, *.vhdx, *.e01, *.raw, *.img, *.dd, etc.)
#   - logs (*.log, *.trace, etc.)
#   - credentials (*.key, *.pem, *.env, tokens, secrets)
#   - staging/import folders (ui-output, testdata, staging, import)
#   - target debug files (*.pdb, *.d, *.rlib, *.rmeta, locks)
#   - existing untracked versioned release binaries (e.g. kdft-v*-windows-x64.*)
$BlacklistPatterns = @(
    '\.(sqlite|db|kdft\.sqlite|sqlite3|db3|sqlite-wal|sqlite-shm)$',
    '\.(vhd|vhdx|e01|raw|img|dd|aff|aff4|iso|bin)$',
    '\.(log|trace)$',
    '(\.env|\.key|\.pem|\.crt|token|secret|credential)',
    '\.(pdb|d|rlib|rmeta|cargo-lock|cargo-build-lock|cargo-artifact-lock)$',
    '^kdft-v[^\\/]+-windows-x64(\.exe|\.zip)$',
    '^kdft\.pdb$',
    '(ui-output|testdata|staging|import)'
)

function Test-IsBlacklisted {
    param([string]$FileName, [string]$RelativePath)

    foreach ($pattern in $BlacklistPatterns) {
        if ($FileName -match $pattern -or $RelativePath -match $pattern) {
            return $pattern
        }
    }
    return $null
}

# -----------------------------------------------------------------------------
# 3. Git Provenance and Dirty-State Disclosure
# -----------------------------------------------------------------------------
function Get-GitProvenance {
    param([string]$RepoPath)

    $info = [ordered]@{
        Available      = $false
        Commit         = "UNKNOWN"
        CommitShort    = "UNKNOWN"
        Branch         = "UNKNOWN"
        IsDirty        = $false
        StatusSummary  = "Git metadata unavailable"
        StatusEntries  = @()
    }

    $gitCmd = Get-Command "git" -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        $info.StatusSummary = "git command not found on PATH"
        return $info
    }

    $prevLocation = Get-Location
    try {
        Set-Location -LiteralPath $RepoPath

        $commitOutput = & git rev-parse HEAD 2>&1
        if ($LASTEXITCODE -eq 0 -and $commitOutput) {
            $info.Commit = ($commitOutput | Out-String).Trim()
            $info.CommitShort = if ($info.Commit.Length -ge 10) { $info.Commit.Substring(0, 10) } else { $info.Commit }
            $info.Available = $true
        }

        $branchOutput = & git rev-parse --abbrev-ref HEAD 2>&1
        if ($LASTEXITCODE -eq 0 -and $branchOutput) {
            $info.Branch = ($branchOutput | Out-String).Trim()
        }

        $statusOutput = & git status --porcelain 2>&1
        if ($LASTEXITCODE -eq 0) {
            $rawStatus = ($statusOutput | Out-String).Trim()
            if ($rawStatus.Length -gt 0) {
                $info.IsDirty = $true
                $lines = $rawStatus -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
                $info.StatusEntries = @($lines)
                $info.StatusSummary = "Repository has $($lines.Count) uncommitted/untracked change(s)"
            } else {
                $info.IsDirty = $false
                $info.StatusSummary = "Clean working tree"
            }
        } else {
            $info.IsDirty = $true
            $info.StatusSummary = "git status exited with code $($LASTEXITCODE): $statusOutput"
        }
    } catch {
        $info.IsDirty = $true
        $info.StatusSummary = "Error querying git: $($_.Exception.Message)"
    } finally {
        Set-Location -LiteralPath $prevLocation
    }

    return $info
}

# -----------------------------------------------------------------------------
# 4. Toolchain Discovery
# -----------------------------------------------------------------------------
function Get-ToolchainInfo {
    $info = [ordered]@{
        RustcVersion = "UNKNOWN"
        CargoVersion = "UNKNOWN"
    }
    try {
        $rustcOut = & rustc --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $rustcOut) {
            $info.RustcVersion = ($rustcOut | Out-String).Trim()
        }
    } catch {}

    try {
        $cargoOut = & cargo --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $cargoOut) {
            $info.CargoVersion = ($cargoOut | Out-String).Trim()
        }
    } catch {}

    return $info
}

# -----------------------------------------------------------------------------
# 5. Execution Banner and Provenance Report
# -----------------------------------------------------------------------------
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  KDFT Windows Developer Packaging & Smoke Workflow" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Repository root : $repoRoot"
Write-Host "Dist directory  : $finalDistRoot"

$gitInfo = Get-GitProvenance -RepoPath $repoRoot
Write-Host "Git commit      : $($gitInfo.CommitShort) ($($gitInfo.Commit))"
Write-Host "Git branch      : $($gitInfo.Branch)"
if ($gitInfo.IsDirty) {
    Write-Host "Working tree    : DIRTY ($($gitInfo.StatusSummary))" -ForegroundColor Yellow
} else {
    Write-Host "Working tree    : CLEAN ($($gitInfo.StatusSummary))" -ForegroundColor Green
}

$toolchain = Get-ToolchainInfo
Write-Host "Rust toolchain  : $($toolchain.RustcVersion)"
Write-Host "Cargo toolchain : $($toolchain.CargoVersion)"
Write-Host "----------------------------------------------------------------------"

# Verify required root legal notices
$requiredLegalFiles = @("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES")
foreach ($legal in $requiredLegalFiles) {
    $legalPath = Join-Path $repoRoot $legal
    if (-not (Test-Path -LiteralPath $legalPath)) {
        throw "Safety failure: Required notice file missing from repository root: $legalPath"
    }
}

# -----------------------------------------------------------------------------
# 6. Format Check (cargo fmt --check)
# -----------------------------------------------------------------------------
if ($SkipFmt) {
    Write-Host "[SKIP] Code formatting check skipped (-SkipFmt)." -ForegroundColor DarkGray
} elseif ($DryRun) {
    Write-Host "[DRY-RUN] Would run: cargo fmt --check" -ForegroundColor Yellow
} else {
    Write-Host "[STEP 1/6] Running cargo fmt --check..." -ForegroundColor Cyan
    & cargo fmt --check
    if ($LASTEXITCODE -ne 0) {
        throw "Code formatting check failed with exit code $LASTEXITCODE. Run 'cargo fmt' to resolve."
    }
    Write-Host "Code formatting verified clean." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 7. Smoke Tests
# -----------------------------------------------------------------------------
if ($SkipTests) {
    Write-Host "[SKIP] Smoke tests skipped (-SkipTests)." -ForegroundColor DarkGray
} elseif ($DryRun) {
    Write-Host "[DRY-RUN] Would run smoke tests:" -ForegroundColor Yellow
    foreach ($target in $SmokeTestTargets) {
        Write-Host "          cargo test -p $target" -ForegroundColor Yellow
    }
} else {
    Write-Host "[STEP 2/6] Running selected smoke tests..." -ForegroundColor Cyan
    foreach ($target in $SmokeTestTargets) {
        Write-Host "Running smoke test: cargo test -p $target..."
        & cargo test -p $target
        if ($LASTEXITCODE -ne 0) {
            throw "Smoke test target '$target' failed with exit code $LASTEXITCODE."
        }
    }
    Write-Host "Smoke tests passed successfully." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 8. Release Build (kdft-ui, kdft-desktop, and kdft-cli)
# -----------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ReleaseBinDir)) {
    $targetReleaseDir = Join-Path $repoRoot "target\release"
} else {
    $targetReleaseDir = if ([System.IO.Path]::IsPathRooted($ReleaseBinDir)) {
        [System.IO.Path]::GetFullPath($ReleaseBinDir)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ReleaseBinDir))
    }
}
$uiExeSrc = Join-Path $targetReleaseDir "kdft-ui.exe"
$desktopExeSrc = Join-Path $targetReleaseDir "kdft-desktop.exe"
$cliExeSrc = Join-Path $targetReleaseDir "kdft.exe"

if ($SkipBuild) {
    Write-Host "[SKIP] Release compilation skipped (-SkipBuild)." -ForegroundColor DarkGray
    if (-not $DryRun) {
        if (-not (Test-Path -LiteralPath $uiExeSrc)) {
            throw "Cannot skip build: kdft-ui.exe missing in target/release: $uiExeSrc"
        }
        if (-not (Test-Path -LiteralPath $desktopExeSrc)) {
            throw "Cannot skip build: kdft-desktop.exe missing in target/release: $desktopExeSrc"
        }
        if (-not (Test-Path -LiteralPath $cliExeSrc)) {
            throw "Cannot skip build: kdft.exe missing in target/release: $cliExeSrc"
        }
    }
} elseif ($DryRun) {
    Write-Host "[DRY-RUN] Would build release binaries:" -ForegroundColor Yellow
    Write-Host "          cargo build --release -p kdft-ui -p kdft-desktop -p kdft-cli" -ForegroundColor Yellow
} else {
    Write-Host "[STEP 3/6] Building release binaries (kdft-ui, kdft-desktop, kdft-cli)..." -ForegroundColor Cyan
    & cargo build --release -p kdft-ui -p kdft-desktop -p kdft-cli
    if ($LASTEXITCODE -ne 0) {
        throw "Release compilation failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path -LiteralPath $uiExeSrc)) {
        throw "Release build succeeded but kdft-ui.exe was not found at $uiExeSrc"
    }
    if (-not (Test-Path -LiteralPath $desktopExeSrc)) {
        throw "Release build succeeded but kdft-desktop.exe was not found at $desktopExeSrc"
    }
    if (-not (Test-Path -LiteralPath $cliExeSrc)) {
        throw "Release build succeeded but kdft.exe was not found at $cliExeSrc"
    }
    Write-Host "Release binaries compiled successfully." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 9. Packaging Directory Allocation (Guaranteed No Overwrite / No Deletion)
# -----------------------------------------------------------------------------
$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$packageName = "kdft-windows-dev-$timestamp"
$packageDir = Join-Path -Path $finalDistRoot -ChildPath $packageName

# Avoid collision without ever deleting existing packages
$counter = 1
$candidateDir = $packageDir
while (Test-Path -LiteralPath $candidateDir) {
    $candidateDir = Join-Path -Path $finalDistRoot -ChildPath "$packageName-$counter"
    $counter++
}
$finalPackageDir = $candidateDir
$finalPackageName = Split-Path -Leaf $finalPackageDir

if ($DryRun) {
    Write-Host "[DRY-RUN] Package destination would be: $finalPackageDir" -ForegroundColor Yellow
} else {
    Write-Host "[STEP 4/6] Creating package directory: $finalPackageDir" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $finalDistRoot)) {
        New-Item -ItemType Directory -Path $finalDistRoot -Force -ErrorAction Stop | Out-Null
    }
    New-Item -ItemType Directory -Path $finalPackageDir -ErrorAction Stop | Out-Null
}

# -----------------------------------------------------------------------------
# 10. Copy Runtime Files & Generate Package Documentation
# -----------------------------------------------------------------------------
$packageReadmeContent = @"
===============================================================================
KDFT Windows Developer Package ($finalPackageName)
===============================================================================

This distribution contains three distinct KDFT front-end binaries built from
source. The native desktop application is the primary examiner surface.

1. DESKTOP (kdft-desktop.exe)
   - Role: Primary native, bounded-memory case and evidence workflow.
   - Purpose: Create or open a KDFT case, attach a file/image or folder, choose
     content/email/browser parsing options, start or cancel background
     processing, and browse bounded evidence and result pages.
   - Execution Model: Native standalone GUI window (egui/eframe). It never
     binds a TCP port and never opens a browser or WebView.
   - Bounded Memory Guarantee: Result and evidence grids use keyset paging
     (defaults to 200 rows and is strictly capped at 1,000 per result page).
   - Usage:
       .\kdft-desktop.exe
       .\kdft-desktop.exe C:\cases\sample.kdft.sqlite
   - Current Processing Scope: Base filesystem inventory/content capture with
     optional email and browser parsing. Results remain explicitly marked as
     partial or truncated when complete forensic coverage is not established.

2. WORKBENCH (kdft-ui.exe)
   - Role: Optional browser-assisted interface retained during native migration.
   - Purpose: Access workbench-only processors, search, inspection, timeline,
     bookmarking, and report surfaces not yet migrated to the native UI.
   - Execution Model: Launches a local loopback HTTP server (127.0.0.1:[port])
     and connects through a local browser. It is not required to run Desktop.
   - Usage:
       .\kdft-ui.exe
       .\kdft-ui.exe --open
       .\kdft-ui.exe --case C:\cases\sample.kdft.sqlite
       .\kdft-ui.exe --port 8777

3. COMMAND-LINE INTERFACE (kdft.exe)
   - Role: Scriptable command-line forensic workflows and automation.
   - Purpose: Preserve non-GUI local case and evidence operations for terminal,
     batch, and integration use alongside the desktop and browser workbench.
   - Execution Model: Local command-line process. It does not require the
     desktop application or browser workbench and opens no network sockets.
   - Usage:
       .\kdft.exe --help

-------------------------------------------------------------------------------
SECURITY & INTEGRITY BOUNDARIES
-------------------------------------------------------------------------------
- None of these binaries requires Internet access.
- kdft-desktop.exe binds ZERO network sockets.
- kdft-ui.exe binds exclusively to loopback (127.0.0.1 or ::1).
- kdft.exe binds ZERO network sockets.
- This package contains NO case databases, evidence images, logs, or credentials.
- All files can be verified using the accompanying SHA256SUMS.txt or manifest.json.

-------------------------------------------------------------------------------
VERIFICATION (PowerShell)
-------------------------------------------------------------------------------
  Get-FileHash -Algorithm SHA256 (Get-ChildItem -File)
  # Or compare directly with SHA256SUMS.txt
===============================================================================
"@

if ($DryRun) {
    Write-Host "[DRY-RUN] Files planned for inclusion:" -ForegroundColor Yellow
    Write-Host "          - kdft-desktop.exe (Primary Native Case/Evidence Workflow)"
    Write-Host "          - kdft-ui.exe      (Optional Browser-Assisted Workbench)"
    Write-Host "          - kdft.exe         (Command-Line Interface)"
    Write-Host "          - LICENSE"
    Write-Host "          - NOTICE"
    Write-Host "          - THIRD_PARTY_NOTICES"
    Write-Host "          - README.txt       (Component roles & launch guide)"
    Write-Host "          - manifest.json    (Machine-readable provenance manifest)"
    Write-Host "          - SHA256SUMS.txt   (SHA-256 hashes of all files)"
} else {
    Write-Host "[STEP 5/6] Staging runtime binaries and documentation..." -ForegroundColor Cyan

    # Copy release binaries
    Copy-Item -LiteralPath $uiExeSrc -Destination (Join-Path $finalPackageDir "kdft-ui.exe") -ErrorAction Stop
    Copy-Item -LiteralPath $desktopExeSrc -Destination (Join-Path $finalPackageDir "kdft-desktop.exe") -ErrorAction Stop
    Copy-Item -LiteralPath $cliExeSrc -Destination (Join-Path $finalPackageDir "kdft.exe") -ErrorAction Stop

    # Copy legal notices
    foreach ($legal in $requiredLegalFiles) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $legal) -Destination (Join-Path $finalPackageDir $legal) -ErrorAction Stop
    }

    # Write package README.txt
    $packageReadmePath = Join-Path $finalPackageDir "README.txt"
    [System.IO.File]::WriteAllText($packageReadmePath, $packageReadmeContent, [System.Text.Encoding]::UTF8)

    # -------------------------------------------------------------------------
    # 11. Automated Blacklist Audit (Defense-in-Depth)
    # -------------------------------------------------------------------------
    Write-Host "Auditing staged package against safety blacklists..."
    $stagedFiles = Get-ChildItem -LiteralPath $finalPackageDir -File
    foreach ($file in $stagedFiles) {
        $matchedPattern = Test-IsBlacklisted -FileName $file.Name -RelativePath $file.Name
        if ($null -ne $matchedPattern) {
            throw "SECURITY VIOLATION: Blacklisted file detected in package: $($file.FullName) (Matched: $matchedPattern)"
        }
    }
    Write-Host "Blacklist audit passed: 0 forbidden files present." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 12. Manifest Construction & SHA-256 Hashing
# -----------------------------------------------------------------------------
$manifestObject = [ordered]@{
    manifest_version  = "1.0"
    package_name      = $finalPackageName
    created_at_utc    = [DateTime]::UtcNow.ToString("o")
    target_platform   = "x86_64-pc-windows-msvc"
    distribution_type = "Windows Developer Package"
    generator         = "scripts/package-windows-dev.ps1"
    components        = [ordered]@{
        workbench = [ordered]@{
            binary          = "kdft-ui.exe"
            role            = "Workbench (Optional Browser-Assisted Analysis UI)"
            description     = "Optional browser-assisted forensic workbench retained for processors and investigation surfaces that have not yet migrated to the native desktop."
            execution_mode  = "Browser-assisted loopback web server"
            network_binding = "Loopback only (127.0.0.1 / [::1])"
            access_mode     = "Read/Write case operations, live evidence ingestion, forensic processing"
            recommended_for = "Examiners who temporarily need a workbench-only processor or investigation surface"
        }
        desktop   = [ordered]@{
            binary          = "kdft-desktop.exe"
            role            = "Desktop (Primary Native Case and Evidence Workflow)"
            description     = "Native standalone GUI (egui/eframe) for creating/opening cases, attaching evidence, running cancellable base processing with optional email/browser parsing, and browsing bounded evidence/result pages. It does not bind any network ports or start a web server."
            execution_mode  = "Native GUI window (egui/eframe)"
            network_binding = "None (zero network sockets opened)"
            access_mode     = "Read/write case creation, evidence attachment, processing, and bounded read-only result projections"
            recommended_for = "Primary native examiner workflow and bounded-memory processing/review"
        }
        cli       = [ordered]@{
            binary          = "kdft.exe"
            role            = "CLI (Command-Line Forensic Workflows)"
            description     = "Scriptable local forensic case and evidence workflows for terminal, batch, and integration use."
            execution_mode  = "Command-line process"
            network_binding = "None (zero network sockets opened)"
            access_mode     = "Local case and evidence operations"
            recommended_for = "Automation, scripting, terminal workflows, and integrations"
        }
    }
    git_provenance    = [ordered]@{
        commit              = $gitInfo.Commit
        commit_short        = $gitInfo.CommitShort
        branch              = $gitInfo.Branch
        is_dirty            = $gitInfo.IsDirty
        status_summary      = $gitInfo.StatusSummary
        uncommitted_changes = $gitInfo.StatusEntries
    }
    toolchain         = [ordered]@{
        rustc = $toolchain.RustcVersion
        cargo = $toolchain.CargoVersion
    }
    files             = @()
}

if ($DryRun) {
    # Validate manifest serialization in dry-run
    $dryRunJson = $manifestObject | ConvertTo-Json -Depth 6
    if (-not $dryRunJson) {
        throw "Dry-run failure: Manifest JSON serialization failed."
    }
    Write-Host "[DRY-RUN] Manifest schema serialization verified." -ForegroundColor Green
} else {
    Write-Host "[STEP 6/6] Computing SHA-256 hashes and generating manifest.json..." -ForegroundColor Cyan

    $manifestPath = Join-Path $finalPackageDir "manifest.json"

    # Compute hashes for payload files (excluding manifest.json and SHA256SUMS.txt)
    $payloadFiles = Get-ChildItem -LiteralPath $finalPackageDir -File | Where-Object {
        $_.Name -ne "SHA256SUMS.txt" -and $_.Name -ne "manifest.json"
    } | Sort-Object Name

    $fileRecords = @()
    $hashLines = @()

    foreach ($file in $payloadFiles) {
        $hashResult = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop
        $hashLower = $hashResult.Hash.ToLowerInvariant()
        $hashLines += "$hashLower  $($file.Name)"

        $fileRecords += [ordered]@{
            path       = $file.Name
            size_bytes = $file.Length
            sha256     = $hashLower
        }
    }

    # Populate and write manifest.json
    $manifestObject.files = $fileRecords
    $manifestJson = $manifestObject | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, [System.Text.Encoding]::UTF8)

    # Compute manifest.json hash and record in SHA256SUMS.txt
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $hashLines += "$manifestHash  manifest.json"

    $sumsPath = Join-Path $finalPackageDir "SHA256SUMS.txt"
    $sumsContent = ($hashLines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($sumsPath, $sumsContent, [System.Text.Encoding]::UTF8)

    Write-Host "Generated SHA256SUMS.txt and manifest.json successfully." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 13. Optional Zip Archive Creation
# -----------------------------------------------------------------------------
if ($Zip) {
    $zipDestination = "$finalPackageDir.zip"
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would create zip archive: $zipDestination" -ForegroundColor Yellow
    } else {
        Write-Host "Creating compressed archive: $zipDestination..." -ForegroundColor Cyan
        if (Test-Path -LiteralPath $zipDestination) {
            throw "Safety failure: Destination zip archive already exists: $zipDestination"
        }
        Compress-Archive -LiteralPath $finalPackageDir -DestinationPath $zipDestination -CompressionLevel Optimal -ErrorAction Stop
        $zipHash = (Get-FileHash -LiteralPath $zipDestination -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Write-Host "Zip archive created. SHA256: $zipHash" -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------------
# 14. Completion Summary
# -----------------------------------------------------------------------------
Write-Host "======================================================================" -ForegroundColor Green
if ($DryRun) {
    Write-Host "  [DRY-RUN SUCCESS] All prerequisites and validations passed." -ForegroundColor Green
    Write-Host "  No files were modified, compiled, or written to dist/." -ForegroundColor Green
} else {
    Write-Host "  [PACKAGE SUCCESS] Windows developer package created successfully." -ForegroundColor Green
    Write-Host "  Location: $finalPackageDir" -ForegroundColor Green
    if ($Zip) {
        Write-Host "  Zip file: $finalPackageDir.zip" -ForegroundColor Green
    }
}
Write-Host "======================================================================" -ForegroundColor Green
