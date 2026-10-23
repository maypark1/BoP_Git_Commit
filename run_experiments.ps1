$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force results | Out-Null
function Save-GoOutput {
    param([string]$OutputFile, [string[]]$GoArgs)
    & go @GoArgs 2>&1 | Out-File -Encoding utf8 $OutputFile
    if ($LASTEXITCODE -ne 0) { throw "go failed: $($GoArgs -join ' ')" }
}
& go version | Out-File -Encoding utf8 results/environment.txt
if ($LASTEXITCODE -ne 0) { throw "go version failed" }
& go env GOOS GOARCH | Out-File -Append -Encoding utf8 results/environment.txt
Get-CimInstance Win32_Processor | Select-Object Name | Out-File -Append results/environment.txt
Save-GoOutput -OutputFile results/correctness.txt -GoArgs @('test','-count=1','-v','./...')
Save-GoOutput -OutputFile results/demo.txt -GoArgs @('run','.')
Save-GoOutput -OutputFile results/time_results.txt -GoArgs @('test','-run','^$','-bench','^Benchmark(MLDSA|Ed25519|Concat|BoP)(KeyGen|Sign|Verify)$','-benchtime=1s','-count=5')
Save-GoOutput -OutputFile results/memory_results.txt -GoArgs @('test','-run','^$','-bench','^BenchmarkMemory(Concat|BoP)(Sign|Verify)$','-benchmem','-benchtime=1s','-count=5')
Save-GoOutput -OutputFile results/size_results.txt -GoArgs @('test','-run','^TestSignatureSizes$','-v')
Write-Host "Completed. Results are in results/."
