param([Parameter(Mandatory=$true)][string]$Executable,
      [Parameter(Mandatory=$true)][string]$QtRoot,
      [Parameter(Mandatory=$true)][string]$MingwRoot,
      [Parameter(Mandatory=$true)][string]$OpenSSLRoot,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
New-Item -Force -ItemType Directory $OutputDirectory | Out-Null
$report=[ordered]@{kind='Windows Qt startup diagnosis';status='NOT_RUN';platform='offscreen';imports=@()}
$search=@((Split-Path $Executable),"$MingwRoot/bin","$QtRoot/bin","$OpenSSLRoot/bin","$env:WINDIR/System32")
$queue=[System.Collections.Generic.Queue[string]]::new()
$seen=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$queue.Enqueue($Executable)
while ($queue.Count -gt 0 -and $seen.Count -lt 128) {
 $binary=$queue.Dequeue()
 if (-not $seen.Add($binary)) { continue }
 $dump=& "$MingwRoot/bin/objdump.exe" -p $binary
 foreach ($line in $dump) {
  if ($line -notmatch 'DLL Name:\s*(\S+)') { continue }
  $name=$Matches[1];$resolved=$null
  foreach ($directory in $search) {
   $candidate=Join-Path $directory $name
   if (Test-Path -LiteralPath $candidate -PathType Leaf) { $resolved=(Resolve-Path -LiteralPath $candidate).Path;break }
  }
  $report.imports+=@{binary=(Split-Path $binary -Leaf);dll=$name;resolved=$resolved}
  if ($resolved -and -not $resolved.StartsWith("$env:WINDIR\",[System.StringComparison]::OrdinalIgnoreCase)) { $queue.Enqueue($resolved) }
 }
}
# Prevent a native loader dialog from blocking unattended diagnosis.
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class DmashErrorMode { [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode); }'
$oldMode=[DmashErrorMode]::SetErrorMode(0x8003)
try {
 $info=[System.Diagnostics.ProcessStartInfo]::new($Executable)
 $info.ArgumentList.Add('disconnectedInventory')
 $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.Environment['QT_QPA_PLATFORM']='offscreen'
 $info.Environment['QT_DEBUG_PLUGINS']='1'
 $process=[System.Diagnostics.Process]::new();$process.StartInfo=$info
 try {
  [void]$process.Start()
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(30000)) { $process.Kill($true);$process.WaitForExit();$report.status='TIMEOUT' }
  else { $report.status='EXITED' }
  $exit=[int]$process.ExitCode
  $report.exitCode=$exit
  $report.exitCodeHex='0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes($exit),0)
  [IO.File]::WriteAllText("$OutputDirectory/direct.stdout.log",$stdout.GetAwaiter().GetResult())
  [IO.File]::WriteAllText("$OutputDirectory/direct.stderr.log",$stderr.GetAwaiter().GetResult())
 } catch {
  $report.status='START_FAILED';$report.failureClass=$_.Exception.GetType().Name;$report.hresult=$_.Exception.HResult
 } finally { $process.Dispose() }
} finally {
 [void][DmashErrorMode]::SetErrorMode($oldMode)
 $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 "$OutputDirectory/startup.json"
}
