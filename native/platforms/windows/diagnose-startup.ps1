param([Parameter(Mandatory=$true)][string]$Executable,
      [Parameter(Mandatory=$true)][string]$QtRoot,
      [Parameter(Mandatory=$true)][string]$MingwRoot,
      [Parameter(Mandatory=$true)][string]$OpenSSLRoot,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
New-Item -Force -ItemType Directory $OutputDirectory | Out-Null
$Executable=(Resolve-Path -LiteralPath $Executable).Path
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$report=[ordered]@{kind='Windows Qt startup diagnosis';version=2;status='NOT_RUN';platform='offscreen';test='full desktop-controls suite';resolution='filesystem candidates, not a loader trace';imports=@();binaries=@()}
$report.executable=$Executable
$report.path=$env:PATH
$report.workingDirectory=(Get-Location).Path
$search=@((Split-Path $Executable),"$env:WINDIR/System32","$env:WINDIR",(Get-Location).Path)+@($env:PATH -split ';')
$queue=[System.Collections.Generic.Queue[string]]::new()
$seen=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$queue.Enqueue($Executable)
# Keep PE import *symbols*, exports, headers and hashes, rather than inferring
# ABI compatibility from DLL filenames. API-set names need not be disk files.
while ($queue.Count -gt 0 -and $seen.Count -lt 128) {
 $binary=$queue.Dequeue()
 if (-not $seen.Add($binary)) { continue }
 $dump=@(& "$MingwRoot/bin/objdump.exe" -p $binary 2>&1)
 $dumpExit=$LASTEXITCODE
 $leaf=Split-Path $binary -Leaf
 $dump | Set-Content -Encoding utf8 (Join-Path $OutputDirectory "$leaf.pe.txt")
 $report.binaries+=@{path=$binary;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash;bytes=(Get-Item -LiteralPath $binary).Length;objdumpExitCode=$dumpExit}
 if ($dumpExit -ne 0) { continue }
 foreach ($line in $dump) {
  if ($line -notmatch 'DLL Name:\s*(\S+)') { continue }
  $name=$Matches[1];$resolved=$null
  foreach ($directory in $search) {
   if (-not $directory) { continue }
   $candidate=Join-Path $directory $name
   if (Test-Path -LiteralPath $candidate -PathType Leaf) { $resolved=(Resolve-Path -LiteralPath $candidate).Path;break }
  }
  $report.imports+=@{binary=$leaf;dll=$name;resolved=$resolved;apiSet=($name -match '^(api|ext)-ms-')}
  if ($resolved -and -not $resolved.StartsWith("$env:WINDIR\",[System.StringComparison]::OrdinalIgnoreCase)) { $queue.Enqueue($resolved) }
 }
}
& "$MingwRoot/bin/g++.exe" --version 2>&1 | Set-Content -Encoding utf8 "$OutputDirectory/compiler.txt"
& "$QtRoot/bin/qmake.exe" -query 2>&1 | Set-Content -Encoding utf8 "$OutputDirectory/qt-query.txt"
# The build tree can disappear with the CI worker. Preserve the failing exact PE
# for entry point / CRT inspection; runtime DLL provenance is in binaries above.
Copy-Item -LiteralPath $Executable -Destination (Join-Path $OutputDirectory (Split-Path $Executable -Leaf))
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DmashStartupNative {
 [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr process, uint milliseconds);
 [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool GetExitCodeProcess(IntPtr process, out uint code);
}
'@
$oldMode=[DmashStartupNative]::SetErrorMode(0x8003)
$process=$null
$clock=[Diagnostics.Stopwatch]::StartNew()
try {
 $info=[System.Diagnostics.ProcessStartInfo]::new($Executable)
 $info.ArgumentList.Add('-v1')
 # This logger also proves QtTest ran if its CRT stdout handles are unavailable.
 $info.ArgumentList.Add('-o');$info.ArgumentList.Add("$OutputDirectory/direct.qtest.txt,txt")
 $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.Environment['QT_QPA_PLATFORM']='offscreen'
 $info.Environment['QT_DEBUG_PLUGINS']='1'
 $process=[System.Diagnostics.Process]::new();$process.StartInfo=$info
 [void]$process.Start()
 $report.pid=$process.Id
 # Retain the actual native handle before waiting. Do not synthesize an exit
 # code from $LASTEXITCODE, a nullable property, or the wait call's boolean.
 $handle=$process.SafeHandle.DangerousGetHandle()
 $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 $wait=[DmashStartupNative]::WaitForSingleObject($handle,30000)
 $report.waitResultHex='0x{0:X8}' -f $wait
 if ($wait -eq 258) {
  $report.status='TIMEOUT'
  $process.Kill($true)
  $report.killWaitResult=[DmashStartupNative]::WaitForSingleObject($handle,5000)
 } elseif ($wait -eq 0) { $report.status='EXITED' }
 else { $report.status='WAIT_FAILED';$report.waitError=[Runtime.InteropServices.Marshal]::GetLastWin32Error() }
 if ($wait -eq 0 -or ($report.Contains('killWaitResult') -and $report.killWaitResult -eq 0)) {
  [uint32]$nativeCode=0
  if (-not [DmashStartupNative]::GetExitCodeProcess($handle,[ref]$nativeCode)) {
   throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  $report.exitCode=$nativeCode
  $report.exitCodeHex='0x{0:X8}' -f $nativeCode
  $process.Refresh()
  $report.dotNetExitCode=$process.ExitCode
 }
 # Descendants can retain inherited pipe handles. Never make collection itself
 # unbounded, and distinguish unavailable/incomplete output from empty output.
 foreach ($stream in @(@{name='stdout';task=$stdout},@{name='stderr';task=$stderr})) {
  $complete=$stream.task.Wait(5000)
  $report[$stream.name+'Complete']=$complete
  if ($complete) {
   $content=$stream.task.GetAwaiter().GetResult()
   [IO.File]::WriteAllText("$OutputDirectory/direct.$($stream.name).log",$content)
   $report[$stream.name+'Characters']=$content.Length
  }
 }
 $log="$OutputDirectory/direct.qtest.txt"
 $report.qtestLogPresent=Test-Path -LiteralPath $log
 $report.qtestBannerObserved=$false
 $report.qtestTotalsObserved=$false
 if ($report.qtestLogPresent) {
  $content=[IO.File]::ReadAllText($log)
  $report.qtestBannerObserved=$content -match 'Start testing of Controls'
  $report.qtestTotalsObserved=$content -match 'Totals:\s+\d+ passed,\s+\d+ failed'
 }
 $report.outcome=if ($report.status -ne 'EXITED') { $report.status } elseif ($report.exitCode -ne 0) { 'NONZERO_EXIT' } elseif (-not $report.qtestBannerObserved -or -not $report.qtestTotalsObserved) { 'ZERO_EXIT_WITHOUT_QTEST_COMPLETION' } else { 'QTEST_COMPLETED' }
} catch {
 $report.status='DIAGNOSIS_FAILED';$report.failureClass=$_.Exception.GetType().Name;$report.hresult=$_.Exception.HResult;$report.failure=$_.Exception.Message
} finally {
 $report.elapsedMilliseconds=$clock.ElapsedMilliseconds
 if ($process) { $process.Dispose() }
 [void][DmashStartupNative]::SetErrorMode($oldMode)
 $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 "$OutputDirectory/startup.json"
}
