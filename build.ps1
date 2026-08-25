param(
  [string]$NdkRoot = $env:ANDROID_NDK_ROOT,
  [int]$Api = 35
)

$ErrorActionPreference = "Stop"
$project = "PD2415-BP2A.250605.031.A3-exact"
$toolchain = Join-Path $NdkRoot "toolchains\\llvm\\prebuilt\\windows-x86_64\\bin"
$cc = Join-Path $toolchain "aarch64-linux-android$Api-clang.cmd"
$outDir = Join-Path $PSScriptRoot "build\\$project\\bin"
$embedDir = Join-Path $PSScriptRoot "build\\embed"
$candidate = "build\\$project\\bin\\200smt6991"

if (-not (Test-Path -LiteralPath $cc)) {
  throw "NDK compiler not found: $cc"
}

New-Item -ItemType Directory -Force $outDir, $embedDir | Out-Null
Push-Location $PSScriptRoot
try {
  & $cc --version
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }

  $suArgs = @(
    "-O2", "-g0", "-Wall", "-Wextra", "-Isrc", "-fPIE", "-pie",
    "src\\su_daemon.c", "-o", "build\\embed\\su_daemon_aarch64_pie"
  )
  & $cc @suArgs
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }

  $candidateArgs = @(
    "-O2", "-g0", "-Wall", "-Wextra",
    "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-unused-function",
    "-Isrc", "-DREFERENCE_STANDALONE=1", "-fPIE",
    "src\\main.c", "src\\util.c", "src\\slide.c", "src\\fops.c",
    "src\\pipe.c", "src\\root.c", "src\\preflight.c", "src\\carrier.c",
    "src\\runtime_sha256.c", "src\\carrier_payload.S", "src\\preload.c",
    "src\\su_blob.S", "src\\wallpaper_blob.S", "src\\entry.c", "-pie",
    "-o", $candidate, "-pthread"
  )
  & $cc @candidateArgs
  exit $LASTEXITCODE
}
finally {
  Pop-Location
}
