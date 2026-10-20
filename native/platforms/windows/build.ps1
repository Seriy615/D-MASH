# Windows 11/Server2025 x64, owned Qt6.12 MinGW13.1 + OpenSSL3.5.9 + QuickJS.
param([Parameter(Mandatory=$true)][string]$QtRoot,
      [Parameter(Mandatory=$true)][string]$MingwRoot,
      [Parameter(Mandatory=$true)][string]$BuildRoot,
      [Parameter(Mandatory=$true)][string]$OpenSSLRoot,
      [Parameter(Mandatory=$true)][string]$QuickJSSource)
$ErrorActionPreference='Stop'
$Repo=(Resolve-Path "$PSScriptRoot/../../..").Path
$env:PATH="$MingwRoot/bin;$QtRoot/bin;$OpenSSLRoot/bin;$env:PATH"
if (-not (Test-Path "$QtRoot/lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake")) { throw 'Qt6.12 Widgets kit required' }
# FindOpenSSL4.2 MinGW assigns OPENSSL_CRYPTO_LIBRARY from its LIB_EAY cache.
$Common=@("-DCMAKE_PREFIX_PATH=$QtRoot", "-DOPENSSL_ROOT_DIR=$OpenSSLRoot", "-DOPENSSL_INCLUDE_DIR=$OpenSSLRoot/include", "-DLIB_EAY:FILEPATH=$OpenSSLRoot/lib/libcrypto.dll.a", "-DSSL_EAY:FILEPATH=$OpenSSLRoot/lib/libssl.dll.a", "-DOPENSSL_CRYPTO_LIBRARY=$OpenSSLRoot/lib/libcrypto.dll.a", '-DBUILD_TESTING=ON', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
cmake -S "$Repo/native/platforms/desktop" -B "$BuildRoot/desktop" -G Ninja @Common "-DDMASH_ACCOUNT_QUICKJS_DIR=$QuickJSSource"
if ($LASTEXITCODE) { throw 'Desktop configure failed' }
cmake --build "$BuildRoot/desktop" --target dmash-desktop dmash_desktop_ui_test --parallel 2
if ($LASTEXITCODE) { throw 'Desktop build failed' }
New-Item -Force -ItemType Directory "$HOME/.cache/dmash-native-20261020" | Out-Null
$desktopDiagnostics="$BuildRoot/diagnostics/desktop"
New-Item -Force -ItemType Directory $desktopDiagnostics | Out-Null
# JUnit retains CTest's termination reason even when the process emits nothing.
ctest --test-dir "$BuildRoot/desktop" -R desktop-controls --output-on-failure --verbose --output-junit "$desktopDiagnostics/ctest.xml"
$desktopTestExit=$LASTEXITCODE
if ($desktopTestExit -ne 0) {
 [IO.File]::WriteAllText("$desktopDiagnostics/ctest-exit.txt",[string]$desktopTestExit)
 foreach ($file in @('CMakeCache.txt','build.ninja','CMakeFiles/rules.ninja','compile_commands.json')) {
  $source=Join-Path "$BuildRoot/desktop" $file
  if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $desktopDiagnostics (Split-Path $file -Leaf)) }
 }
 Copy-Item -LiteralPath $PSCommandPath,"$PSScriptRoot/diagnose-startup.ps1" -Destination $desktopDiagnostics
 try {
  & "$PSScriptRoot/diagnose-startup.ps1" -Executable "$BuildRoot/desktop/dmash_desktop_ui_test.exe" -QtRoot $QtRoot -MingwRoot $MingwRoot -OpenSSLRoot $OpenSSLRoot -OutputDirectory $desktopDiagnostics
 } catch {
  # A diagnostic error must not replace or accidentally clear the CTest failure.
  $_ | Out-String | Set-Content -Encoding utf8 "$desktopDiagnostics/diagnosis-error.txt"
 }
 throw "Windows UI tests failed (CTest exit $desktopTestExit); bounded native exit / QtTest / PE diagnostics captured"
}
cmake -S "$Repo/native/account" -B "$BuildRoot/account" -G Ninja @Common "-DDMASH_ACCOUNT_QUICKJS_DIR=$QuickJSSource"
if ($LASTEXITCODE) { throw 'Account/broker configure failed' }
cmake --build "$BuildRoot/account" --parallel 2
if ($LASTEXITCODE) { throw 'Account/broker build failed' }
ctest --test-dir "$BuildRoot/account" --output-on-failure
if ($LASTEXITCODE) { throw 'Windows Account/broker tests failed' }
cmake -S "$Repo/native" -B "$BuildRoot/node" -G Ninja @Common "-DDMASH_QUICKJS_DIR=$QuickJSSource"
if ($LASTEXITCODE) { throw 'Node configure failed' }
cmake --build "$BuildRoot/node" --parallel 2
if ($LASTEXITCODE) { throw 'Node build failed' }
ctest --test-dir "$BuildRoot/node" --output-on-failure
if ($LASTEXITCODE) { throw 'Windows native tests failed' }
cmake --install "$BuildRoot/desktop" --prefix "$BuildRoot/package"
$credentialHost="$BuildRoot/desktop/dmash-credential-host.exe"
Copy-Item $credentialHost "$BuildRoot/package/bin/"
Copy-Item "$BuildRoot/node/dmash-node-host.exe" "$BuildRoot/package/bin/"
Copy-Item "$OpenSSLRoot/bin/libcrypto-3-x64.dll","$OpenSSLRoot/bin/libssl-3-x64.dll" "$BuildRoot/package/bin/"
& "$QtRoot/bin/windeployqt.exe" --no-translations --compiler-runtime "$BuildRoot/package/bin/dmash-desktop.exe"
if ($LASTEXITCODE) { throw 'Desktop deploy failed' }
& "$QtRoot/bin/windeployqt.exe" --no-translations --compiler-runtime "$BuildRoot/package/bin/dmash-credential-host.exe"
if ($LASTEXITCODE) { throw 'Credential host deploy failed' }
& "$QtRoot/bin/windeployqt.exe" --no-translations --compiler-runtime "$BuildRoot/package/bin/dmash-node-host.exe"
if ($LASTEXITCODE) { throw 'Node deploy failed' }
Write-Output 'Development package built/tested. Real Account/Node integration and Windows lifecycle acceptance are separate gates.'
