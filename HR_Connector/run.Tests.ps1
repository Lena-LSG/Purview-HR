# BEGIN: Test GetOrCreateMetadata
# Test case 1: Existing metadata with matching file hash
$existingMetadata = [FileMetadata]::new()
$existingMetadata.FileHash = "ABC123"
$existingMetadata.NoOfRowsWritten = 10
$existingMetadata.Service = "PushConnector"
$existingMetadata.LastModTime = "2025-02-17T12:34:56"
$existingMetadata | ConvertTo-Json | Out-File "C:\Temp\ABC123-metadata.txt"
$metadata1 = GetOrCreateMetadata -FileName "C:\path\to\file.txt"
if ($metadata1.FileHash -eq "ABC123" -and $metadata1.NoOfRowsWritten -eq 10 -and $metadata1.Service -eq "PushConnector" -and $metadata1.LastModTime -eq "2025-02-17T12:34:56") {
    Write-Host "Test case 1 passed"
} else {
    Write-Host "Test case 1 failed"
}

# Test case 2: Existing metadata with different file hash
$existingMetadata.FileHash = "DEF456"
$existingMetadata | ConvertTo-Json | Out-File "C:\Temp\DEF456-metadata.txt"
$metadata2 = GetOrCreateMetadata -FileName "C:\path\to\file.txt"
if ($metadata2.FileHash -eq "ABC123" -and $metadata2.NoOfRowsWritten -eq 0 -and $metadata2.Service -eq "PushConnector" -and $metadata2.LastModTime -ne "2025-02-17T12:34:56") {
    Write-Host "Test case 2 passed"
} else {
    Write-Host "Test case 2 failed"
}

# Test case 3: New metadata
Remove-Item "C:\Temp\ABC123-metadata.txt"
$metadata3 = GetOrCreateMetadata -FileName "C:\path\to\file.txt"
if ($metadata3.FileHash -eq "ABC123" -and $metadata3.NoOfRowsWritten -eq 0 -and $metadata3.Service -eq "PushConnector" -and $metadata3.LastModTime -ne "2025-02-17T12:34:56") {
    Write-Host "Test case 3 passed"
} else {
    Write-Host "Test case 3 failed"
}
# END: Test GetOrCreateMetadata

# BEGIN: Test UpdateMetadata
# Test case 1: Update metadata with valid input
UpdateMetadata -FileName "C:\path\to\file.txt" -noOfRowsWritten 100
$updatedMetadata = [FileMetadata](Get-Content "C:\Temp\ABC123-metadata.txt" | Out-String | ConvertFrom-Json)
if ($updatedMetadata.FileHash -eq "ABC123" -and $updatedMetadata.NoOfRowsWritten -eq 100 -and $updatedMetadata.Service -eq "PushConnector" -and $updatedMetadata.LastModTime -ne "2025-02-17T12:34:56") {
    Write-Host "Test case 1 passed"
} else {
    Write-Host "Test case 1 failed"
}
# END: Test UpdateMetadata

# BEGIN: Test HandleObsoleteMetadata
# Test case 1: Remove obsolete metadata files
$obsoleteMetadata1 = [FileMetadata]::new()
$obsoleteMetadata1.FileHash = "123456"
$obsoleteMetadata1 | ConvertTo-Json | Out-File "C:\Temp\123456-metadata.txt"
$obsoleteMetadata2 = [FileMetadata]::new()
$obsoleteMetadata2.FileHash = "7890AB"
$obsoleteMetadata2 | ConvertTo-Json | Out-File "C:\Temp\7890AB-metadata.txt"
$obsoleteMetadata3 = [FileMetadata]::new()
$obsoleteMetadata3.FileHash = "CDEF01"
$obsoleteMetadata3 | ConvertTo-Json | Out-File "C:\Temp\CDEF01-metadata.txt"
HandleObsoleteMetadata
if (-not (Test-Path "C:\Temp\123456-metadata.txt") -and -not (Test-Path "C:\Temp\7890AB-metadata.txt") -and -not (Test-Path "C:\Temp\CDEF01-metadata.txt")) {
    Write-Host "Test case 1 passed"
} else {
    Write-Host "Test case 1 failed"
}
# END: Test HandleObsoleteMetadata

# BEGIN: Test ComputeHashForInputFile
# Test case 1: Compute hash for input file
$hash = ComputeHashForInputFile -FileName "C:\path\to\file.txt"
if ($hash -ne $null) {
    Write-Host "Test case 1 passed"
} else {
    Write-Host "Test case 1 failed"
}
# END: Test ComputeHashForInputFile

# BEGIN: Test Get-AccessToken
# Test case 1: Get access token
$accessToken = Get-AccessToken -tenantId "your-tenant-id" -appId "your-app-id" -appSecret "your-app-secret"
if ($accessToken -ne $null) {
    Write-Host "Test case 1 passed"
} else {
    Write-Host "Test case 1 failed"
}
# END: Test Get-AccessToken