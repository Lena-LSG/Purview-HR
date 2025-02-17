<#
.SYNOPSIS
    This script is the entry point for a timer triggered Azure function that connects to an HR system and pushes a CSV file of data to Microsoft Purview using the Microsoft Office 365 Management API.
    
.DESCRIPTION
    The run.ps1 script is part of an HR Connector solution that automates and regularly facilitates the process of extracting user data from an HR system and pushing it to Microsoft Purview.
    The script is designed to be executed as a timer triggered Azure function, which allows it to run at specified intervals.
    
    The script performs the following tasks:
    1. Retrieves an access token from the Entra using client credentials for a service principal.
    2. Downloads the HR data CSV from Azure Blob Storage.
    3. Obtains or creates metadata for the user data file.
    4. Computes the hash for the user data file.
    5. Updates the metadata for the user data file.
    6. Ingests the user data into Microsoft Purview using the Microsoft Office 365 Management API.
    7. Handles obsolete metadata files.
    8. Retries the execution of the script block multiple times until it succeeds or reaches the maximum number of retries.

.PARAMETER Timer
    The timer object that triggers the Azure function. Without this the script will not function correctly as an Azure Function App.

.NOTES
    Author: Lena Gibson (Cyber Security Engineering)
    Created: 17th February 2025
    Last Modified: 17 February 2025
    Version: 1.0

    This script is adapted from Microsoft's sample script for ingestion of HR data into Microsoft Purview. The ability for the script to run as an Azure Function App and functionality to download and ingest a CSV file from Azure Blob Storage has been added.
    Microsoft's original sample script can be found here: https://github.com/microsoft/m365-compliance-connector-sample-scripts/blob/main/sample_script.ps1

#>

# Import the System.Net namespace to use its classes and functions.
using namespace System.Net

# This script is the entry point for a timer triggered Azure function.
param($Timer)
# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()
# Log the start time of the HR connector script.
Write-Host "PowerShell timer trigger function started at: $currentUTCtime"

# Set the value of the $serviceName variable to "PushConnector".
$serviceName = "PushConnector"

# Set the value of the $TmpDirName variable to the path of the temporary directory for the PushConnector.
$TmpDirName = Join-Path -Path $env:TEMP -ChildPath "PushConnectorTemp"


<#
.SYNOPSIS
    Represents metadata for a file.

.DESCRIPTION
    The FileMetadata class defines the properties for storing metadata information about a file.
    
#>
class FileMetadata {
    [string]$FileHash
    [string]$NoOfRowsWritten
    [string]$Service
    [string]$LastModTime
}

<#
.SYNOPSIS
Obtains or creates metadata for a given file.

.DESCRIPTION
This function checks if metadata for a given file exists. If it exists and the file hash matches the computed hash, the existing metadata is returned. Otherwise, a new metadata object is created with the file hash, number of rows written, last modification time, and service name.

.PARAMETER FileName
The name of the input file.

.OUTPUTS
A FileMetadata object containing the metadata for the file.

.EXAMPLE
GetOrCreateMetadata -FileName "C:\path\to\file.txt"
#>
function GetOrCreateMetadata($FileName) {
    HandleObsoleteMetadata  # Remove obsolete metadata files

    $fileHash = ComputeHashForInputFile($FileName)  # Compute hash for the input file

    $metaDataFileName = GetMetaDataFileName($fileHash)  # Get the metadata file name based on the file hash

    if ([System.IO.File]::Exists($metaDataFileName)) {  # Check if the metadata file exists
        $metadata = [FileMetadata](Get-Content $metaDataFileName | Out-String | ConvertFrom-Json)  # Read the metadata from the file

        if ($metadata.FileHash -eq $fileHash) {  # Check if the file hash in the metadata matches the computed hash
            return $metadata  # Return the existing metadata
        }
    }
    
    $newmetadata = [FileMetadata]::new()  # Create a new metadata object
    $newmetadata.FileHash = $fileHash  # Set the file hash in the new metadata
    $newmetadata.NoOfRowsWritten = 0  # Set the number of rows written to 0
    $newmetadata.LastModTime = Get-Date -format "yyyy-MM-ddTHH:mm:ss"  # Set the last modification time to the current time
    $newmetadata.Service = $serviceName  # Set the service name in the new metadata

    return $newmetadata  # Return the new metadata
}

<#
.SYNOPSIS
Returns the metadata file name for a given file hash.

.DESCRIPTION
The GetMetaDataFileName function constructs the metadata file name by joining the temporary directory path with the file hash and the file extension "-metadata.txt".

.PARAMETER FileHash
The hash value of the file for which the metadata file name is to be generated.

.OUTPUTS
System.String
The metadata file name.

.EXAMPLE
GetMetaDataFileName "ABC123"
Returns: "C:\Temp\ABC123-metadata.txt"
#>
function GetMetaDataFileName($FileHash) {
    return Join-Path -Path $TmpDirName -ChildPath "$FileHash-metadata.txt"
}

<#
.SYNOPSIS
Updates the metadata for a file.

.DESCRIPTION
This function updates the metadata for a file, including the file hash, service name, number of rows written, and last modification time.

.PARAMETER FileName
The path of the file for which to update the metadata.

.PARAMETER noOfRowsWritten
The number of rows written to the file.

.EXAMPLE
UpdateMetadata -FileName "C:\Path\To\File.txt" -noOfRowsWritten 100

This example updates the metadata for the file "C:\Path\To\File.txt" with the number of rows written set to 100.

#>
function UpdateMetadata($FileName, $noOfRowsWritten) {
    $filemetaData = [FileMetadata]::new()  # Create a new FileMetadata object
    $fileHash = ComputeHashForInputFile($FileName)  # Compute the hash for the input file
    $filemetaData.FileHash = $fileHash  # Set the file hash in the metadata
    $filemetaData.Service = $serviceName  # Set the service name in the metadata
    $filemetaData.NoOfRowsWritten = $noOfRowsWritten  # Set the number of rows written in the metadata
    $filemetaData.LastModTime = Get-Date -format "yyyy-MM-ddTHH:mm:ss"  # Set the last modification time in the metadata
    $metaDataFilePath = GetMetaDataFileName($fileHash)  # Get the metadata file path based on the file hash
    $filemetaData | ConvertTo-Json -Depth 100 | Out-File $metaDataFilePath  # Convert the metadata to JSON and save it to the metadata file
}

<#
.SYNOPSIS
Handles obsolete metadata files.

.DESCRIPTION
This function removes obsolete metadata files from the specified directory.
Obsolete metadata files are identified based on their last write time and file name pattern.

.PARAMETER TmpDirName
The path to the directory containing the metadata files.

.EXAMPLE
HandleObsoleteMetadata -TmpDirName "C:\Path\To\Directory"

This example removes obsolete metadata files from the specified directory.

#>
function HandleObsoleteMetadata() {
    $timeLimit = (Get-Date).AddDays(-14)  # Set the time limit to 14 days ago
    $filePath = $TmpDirName  # Set the file path to the temporary directory
    Get-ChildItem -Path $filePath -Recurse -Force |  # Get all child items in the directory recursively
    Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt $timeLimit } |  # Filter out non-container items and items older than the time limit
    Where-Object { $_.Name -match '^[a-f0-9]{32}-metadata.txt$' } |  # Filter out items with names matching the pattern of a metadata file
    Remove-Item -Force  # Remove the filtered items
}

<#
.SYNOPSIS
Computes the hash for an input file.

.DESCRIPTION
This function computes the hash for an input file by concatenating the file name and its last write time, and then calculating the hash of the resulting string.

.PARAMETER FileName
The path of the input file.

.OUTPUTS
The computed hash value for the input file.

.EXAMPLE
$hash = ComputeHashForInputFile -FileName "C:\Path\To\File.txt"
#>
function ComputeHashForInputFile($FileName) {
    $stream = [System.IO.MemoryStream]::new()  # Create a new memory stream
    $writer = [System.IO.StreamWriter]::new($stream)  # Create a new stream writer using the memory stream
    $date = ([datetime](Get-ItemProperty -Path $FileName -Name LastWriteTime).lastwritetime).ToString("yyyy-MM-ddTHH:mm:ss")  # Get the last write time of the file and convert it to a string in the specified format
    $writer.write($FileName + $date)  # Concatenates the file name and last write time
    $writer.Flush()  # Flush the writer to ensure all data is written to the stream
    $stream.Position = 0  # Set the position of the stream to the beginning
    $filemetaData = Get-FileHash -InputStream $stream | Select-Object -ExpandProperty Hash  # Calculates the hash of the concatenated string using Get-FileHash
    $stream.Dispose()  # Dispose the memory stream
    $writer.Dispose()  # Dispose the stream writer
    return $filemetaData  # Return the computed hash value
}

<#
.SYNOPSIS
    Retrieves an access token from Entra using client credentials for a service principal.

.DESCRIPTION
    The Get-AccessToken function retrieves an access token by making a request to the OAuth token endpoint using client credentials.
    The access token is required for authenticating and authorizing API requests.

.PARAMETER tenantId
    The ID of the Entra tenant where the application is registered.

.PARAMETER appId
    The ID of the application (client) registered in Entra.

.PARAMETER appSecret
    The secret key of the application.

.OUTPUTS
    System.String
    Returns the access token as a string.

.EXAMPLE
    $accessToken = Get-AccessToken -tenantId "your-tenant-id" -appId "your-app-id" -appSecret "your-app-secret"
#>
function Get-AccessToken {
    param (
        [string] $tenantId,
        [string] $appId,
        [string] $appSecret
    )

    # Access Token Config
    $oAuthTokenEndpoint = "https://login.windows.net/$tenantId/oauth2/token"
    $resource = 'https://microsoft.onmicrosoft.com/4e476d41-2395-42be-89ff-34cb9186a1ac'

    # Token Authorization URI
    $uri = "$($oAuthTokenEndpoint)?api-version=1.0"

    # Access Token Body
    $formData = 
    @{
        client_id     = $appId;
        client_secret = $appSecret;
        grant_type    = 'client_credentials';
        resource      = $resource;
        tenant_id     = $tenantId;
    }

    # Parameters for Access Token call
    $params = 
    @{
        URI         = $uri
        Method      = 'Post'
        ContentType = 'application/x-www-form-urlencoded'
        Body        = $formData
    }

    Write-Host $params

    $response = Invoke-RestMethod @params -ErrorAction Stop
    return $response.access_token
}


<#
.SYNOPSIS
Retries the execution of a script block multiple times until it succeeds or reaches the maximum number of retries.

.DESCRIPTION
The RetryCommand function allows you to retry the execution of a script block in case of failures. It will continue to retry the script block until it succeeds or reaches the maximum number of retries specified.

.PARAMETER ScriptBlock
The script block to be executed and retried.

.PARAMETER Maximum
The maximum number of retries. The default value is 15.

.EXAMPLE
RetryCommand -ScriptBlock { Get-Process -Name "MyProcess" } -Maximum 5
This example retries the execution of the script block, which tries to get the process with the name "MyProcess", for a maximum of 5 times.

#>
function RetryCommand {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [scriptblock]$ScriptBlock,  # The script block to be executed and retried

        [Parameter(Position = 1, Mandatory = $false)]
        [int]$Maximum = 15  # The maximum number of retries. The default value is 15.
    )

    Begin {
        $cnt = 0  # Counter for the number of retries
        $retryTimeout = 60  # Retry timeout in seconds
    }

    Process {
        do {
            $cnt++
            try {
                $ScriptBlock.Invoke()  # Execute the script block
                return  # Return if the script block succeeds
            }
            catch {
                Write-Error $_.Exception.InnerException.Message -ErrorAction Continue  # Write the error message to the console
                Write-Verbose("Will retry in [{0}] seconds" -f $retryTimeout)  # Write a verbose message indicating the retry timeout
                Start-Sleep $retryTimeout  # Wait for the retry timeout
                if ($cnt -lt $Maximum) {
                    Write-Output "Retrying"  # Write a message indicating that a retry is being performed
                }
            }
        } while ($cnt -lt $Maximum)

        throw 'Execution failed.'  # Throw an exception if the maximum number of retries is reached
    }
}

<#
.SYNOPSIS
Uploads a file to Microsoft Purview using the Microsoft 365 Management API.

.DESCRIPTION
The Push-Data function is used to upload a data file to Microsoft Purview. It makes use of the Microsoft 365 Management API to send the file as a multipart form data request. The function requires an access token for authentication, the path to the file to be uploaded, and the job ID for the connector associated job defined in Microsoft Purview.

.PARAMETER access_token
The Entra access token for authentication.

.PARAMETER filePath
The path to the file of HR data to be uploaded.

.PARAMETER jobId
The job ID for the connector associated job defined in Microsoft Purview.

.EXAMPLE
Push-Data -access_token "1234567890" -filePath "C:\path\to\file.csv" -jobId "job123"

This example demonstrates how to use the Push-Data function to upload a file to Microsoft Purview. The access token, file path, and job ID are provided as parameters.

.NOTES
This function requires the System.Net.Http assembly to be loaded.

.LINK
https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
#>
function Push-Data {
    param (
        [string] $access_token,  # Entra access token for authentication
        [string] $filePath,      # Path to the file to be uploaded
        [string] $jobId          # Job ID for the connector associated job defined in Microsoft Purview.
    )
    
    $eventApiURl = "https://webhook.ingestion.office.com"  # Microsoft 365 Management API URL
    $eventApiEndpoint = "api/signals"                     # API endpoint
    
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)  # Collection for query parameters
    $nvCollection.Add('jobid', $jobId)                                          # Add job ID to query parameters
    $uriRequest = [System.UriBuilder]"$eventApiURl/$eventApiEndpoint"            # Build the API request URL
    $uriRequest.Query = $nvCollection.ToString()                                 # Add query parameters to the URL
    
    $fieldName = 'file'  # Field name for the file in the multipart form data
    $url = $uriRequest.Uri.OriginalString  # Final URL for the API request
    
    Add-Type -AssemblyName 'System.Net.Http'  # Add assembly for making HTTP requests
    $client = New-Object System.Net.Http.HttpClient  # Create an HTTP client
    $content = New-Object System.Net.Http.MultipartFormDataContent  # Create multipart form data content
    
    try {
        $fileStream = [System.IO.File]::OpenRead($filePath)  # Open the file for reading
        $fileName = [System.IO.Path]::GetFileName($filePath)  # Get the file name
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)  # Create stream content from the file
        $content.Add($fileContent, $fieldName, $fileName)  # Add the file content to the multipart form data
    }
    catch [System.IO.FileNotFoundException] {
        Write-Error("Csv file not found.")  # Handle file not found error
        return
    }
    catch [System.IO.IOException] {
        Write-Error("Csv file might be open")  # Handle file open error
        return
    }
    catch {
        Write-Error("Error reading from csv file")  # Handle general file reading error
        return
    }
    
    $client.DefaultRequestHeaders.Add("Authorization", "Bearer $access_token")  # Add authorization header
    $client.Timeout = New-Object System.TimeSpan(0, 0, 400)  # Set request timeout
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # Set security protocol to ensure old versions of TLS are not used
        $result = $client.PostAsync($url, $content).Result  # Send the POST request
        
        $status_code = [int]$result.StatusCode  # Get the status code from the HTTP response
        if ($result.IsSuccessStatusCode) {
            Write-Output "Upload Successful"  # Log successful upload
            $responseStr = $result.Content.ReadAsStringAsync().Result  # Get the response body
            if (![string]::IsNullOrWhiteSpace($responseStr)) {
                Write-Output("Body : {0}" -f $responseStr)  # Output the response body to assist with debugging
            }
        }
        elseif ($status_code -eq 0 -or $status_code -eq 501 -or $status_code -eq 503) {
            throw "Service unavailable."  # Handle service unavailable error
        }
        else {
            $errorstring = "Failure with StatusCode [{0}] and ReasonPhrase [{1}]" -f $result.StatusCode, $result.ReasonPhrase
            Write-Error $errorstring  # Handle other errors
            Write-Error("Error body : {0}" -f $result.Content.ReadAsStringAsync().Result)  # Output the error body
            throw $errorstring
        }
    }
    catch {
        Write-Error("Unknown failure while uploading.")  # Handle unknown failure
        throw
    }
    finally {
        if ($null -ne $fileStream) {
            $fileStream.Dispose()  # Dispose the file stream
        }
        if ($null -ne $content) {
            $content.Dispose()  # Dispose the content
        }
        if ($null -ne $client) {
            $client.Dispose()  # Dispose the client
        }
    }
}


<#
.SYNOPSIS
    Sends data in chunks to the Microsoft Office 365 Management API. Specifically the 'api/signals' endpoint. This allows the data to be ingested into Microsoft Purview.

.DESCRIPTION
    The Send-ChunkedData function is used to send data in chunks to the API. It reads a file, splits it into smaller chunks, and sends each chunk to the API for processing. This approach is useful when dealing with large files or when there are limitations on the size of data that can be sent to the API in a single request.

.PARAMETER FileName
    The name of the file to be processed.

.PARAMETER linesperFile
    The number of lines to be included in each chunk.

.EXAMPLE
    Send-ChunkedData -FileName "C:\path\to\file.txt" -linesperFile 1000
    This example sends the data in the file "C:\path\to\file.txt" to the API in chunks of 1000 lines per chunk.

.NOTES
    This function requires the following helper functions:
    - GetOrCreateMetadata: Retrieves or creates metadata for the file.
    - RetryCommand: Executes a script block with retry logic.
    - Get-AccessToken: Retrieves an access token for authentication.
    - Push-Data: Pushes the data to the API.
    - UpdateMetadata: Updates the metadata with the number of rows processed.

#>
function Send-ChunkedData {
    param(
        [string]$FileName,     # The name of the file to be processed
        [int]$linesperFile     # Number of lines to be included in each chunk
    )

    if (!(Test-Path $TmpDirName -PathType Container)) {
        New-Item -ItemType directory -Path $TmpDirName
    }

    $TmpFileName = "\tmp"
    $ext = ".txt"
    $filecount = 1
    $reader = $null
  
    try {
        $reader = [io.file]::OpenText($FileName)   # Open the file for reading
        $metaData = GetOrCreateMetadata($FileName) # Get or create metadata for the file

        try {        
            $header = $reader.ReadLine()    # Read the header line of the file
            $activeLineCount = 0

            # Skip the number of rows already written as per metadata
            while ($activeLineCount -lt $metaData.NoOfRowsWritten -and $reader.EndOfStream -ne $true) {
                $reader.ReadLine() | Out-Null
                $activeLineCount++
            }
            
            Write-Host "Rows already ingested from File Count: $activeLineCount"
            
            while ($reader.EndOfStream -ne $true) {              
                $linecount = 0
                $NewFile = "{0}{1}{2}{3}" -f ($TmpDirName, $TmpFileName, $filecount.ToString("0000"), $ext)   # Generate a new file name for the chunk
                Write-Verbose "Creating file $NewFile"
                $writer = [io.file]::CreateText($NewFile)   # Create a new file for writing
                $filecount++
                
                $writer.WriteLine($header)   # Write the header line to the new file

                while (($linecount -lt $linesperFile) -and ($reader.EndOfStream -ne $true)) {
                    $writer.WriteLine($reader.ReadLine())   # Write lines from the original file to the new file
                    $linecount++
                }

                $activeLineCount = $activeLineCount + $linecount   # Update the count of lines processed
                $writer.Dispose()   # Close the writer and save the new file

                Write-Host "Created file with $linecount records"

                Write-Host "Pushing data to API"
                RetryCommand -ScriptBlock {
                    $access_token = Get-AccessToken -tenantId $env:TenantId -appId $env:AppId -appSecret $env:AppSecret
                    Write-Host "Obtained Token!"
                    Push-Data -access_token $access_token -filePath $NewFile -jobId $env:JobId   # Push the data to the API
                }
                
                # Update metadata
                Write-Host "Updating metadata"
                UpdateMetadata -FileName $FileName -noOfRowsWritten $activeLineCount   # Update the metadata with the number of rows processed  
                Write-Verbose "Deleting file $NewFile"
                Remove-Item $NewFile   # Delete the chunk file
            }
        }
        finally {     
            if ($null -ne $writer) {
                $writer.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

try {
    # Connect using managed identity
    Write-Host "Connecting to Azure using managed identity"
    Connect-AzAccount -Identity

    # Get storage account from resource group
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $env:storageResourceGroup | 
        Where-Object { $_.StorageAccountName -eq $env:StorageAccountName }

    # Download blob using managed identity
    $tempDir = Join-Path $env:TEMP "hrdata"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    $localFilePath = Join-Path $tempDir $env:CsvBlobName

    # Check if the local file exists and remove it if it does
    if (Test-Path $localFilePath) {
        Remove-Item $localFilePath -Force
    }

    Write-Host "Downloading blob to $localFilePath"
    Get-AzStorageBlobContent -Container $env:ContainerName -Blob $env:CsvBlobName -Destination $localFilePath -Context $storageAccount.Context

    # Process the file with chunking and metadata handling
    Write-Host "Sending Chunked Data"
    Send-ChunkedData -FileName $localFilePath -linesperFile 50000

    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force
    
    Write-Host "PowerShell timer trigger function completed at: $((Get-Date).ToUniversalTime())"
}
catch {
    Write-Error "Error in HR data import: $_"
    throw
}
