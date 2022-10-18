pipeline {
    agent any

    stages {
        stage('zipRepo') {
            steps {
                powershell '''
					$sourcePath = "${env:WORKSPACE}/"
					write-host "$sourcePath"
					$destinationPath = Split-Path -Path "$sourcePath"
					$destinationPath += "/${env:JOB_NAME}-${env:BUILD_NUMBER}.zip"
					Write-Host "$destinationPath"
					
                    if(Test-Path -Path $destinationPath -PathType Leaf)
                    {
                        Remove-Item $destinationPath
                    }

                    Add-Type -Assembly \'System.IO.Compression.FileSystem\'
                    $zip = [System.IO.Compression.ZipFile]::Open($destinationPath, \'create\')
                    $files = [IO.Directory]::GetFiles($sourcePath, "*" , [IO.SearchOption]::AllDirectories)
                    foreach($file in $files)
                    {
                        $relPath = $file.Substring($sourcePath.Length).Replace("//", "/").Replace("//", "/") #Linux path check
                        $a = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.Replace("//", "/").Replace("//", "/"), $relPath); # Linux path
                    }
                    $zip.Dispose()
				
				'''
            }
        }
		stage('uploadZip') {
            steps {
                powershell '''
					Write-Host "Received scanning request successfully.."
					
					$sourcePath = "${env:WORKSPACE}"
					$filePath = Split-Path -Path "$sourcePath"
					$filePath += "/${env:JOB_NAME}-${env:BUILD_NUMBER}.zip"
					Write-Host "$destinationPath"

					$buildId = "${env:JOB_NAME}-${env:BUILD_NUMBER}"
					$projectId = $null

					if("$env:Offensive360SastApi_ProjectId" -ne "")
					{
						$projectId = "$env:Offensive360SastApi_ProjectId"
					}

					$projectName = "Zenkins_Project_$buildId"
					$boundary = [System.Guid]::NewGuid().ToString()

					Write-Host "Starting scanning for the project name [$projectName], accessToken [$env:Offensive360SastApi_AccessToken], url [$env:Offensive360SastApi_BaseUrl], buildId [$buildId], filePath [$filePath], boundary [$boundary], projectId [$env:Offensive360SastApi_ProjectId]"

					$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
					$fileContent = [System.Text.Encoding]::GetEncoding(\'iso-8859-1\').GetString($fileBytes)

					$LF = "`r`n"
					$bodyLines = (
						"--$boundary",
						"Content-Disposition: form-data; name=`"projectOrRepoName`"$LF",
						"$projectName",
						"--$boundary",
						"Content-Disposition: form-data; name=`"projectID`"$LF",
						"$projectId",
						"--$boundary",
						"Content-Disposition: form-data; name=`"deleteProjectAndScanAfterScanning`"$LF",
						"false",
						"--$boundary",
						"Content-Disposition: form-data; name=`"projectSource`"; filename=`"$projectName.zip`"",
						"Content-Type: application/x-zip-compressed$LF",
						$fileContent,
						"--$boundary--$LF"
					) -join $LF

					$apiResponse = Invoke-RestMethod -Method Post -Uri ("{0}/app/api/ExternalScan/single-file" -f $env:Offensive360SastApi_BaseUrl.TrimEnd('/')) -ContentType "multipart/form-data; boundary=`"$boundary`"" -Headers @{"Accept" = "application/json"; "Authorization" = "Bearer $env:Offensive360SastApi_AccessToken"} -Body $bodyLines

					write-host ("total vulnerabilities count = {0}" -f $apiResponse.vulnerabilities.length)

					if ($apiResponse.vulnerabilities.length -gt 0 -and "$env:ADO_BreakBuildWhenVulnsFound" -eq \'True\') 
					{
						write-host "\n\n**********************************************************************************************************************"
						write-host ("Offensive 360 vulnerability dashboard : {0}/Scan/showscan-{1}-{2}" -f $env:Offensive360SastUi_BaseUrl.TrimEnd('/'), $apiResponse.projectId, $apiResponse.id)
						write-host "**********************************************************************************************************************\n\n"
						throw [System.Exception] "Vulnerabilities found and breaking the build."
					}
					elseif ($apiResponse.vulnerabilities.length -gt 0 -and "$env:ADO_BreakBuildWhenVulnsFound" -ne \'True\') 
					{
						Write-Warning \'Vulnerabilities found and since ADO_BreakBuildWhenVulnsFound is set to false so continuing to build it.\'
					}
					else
					{
						Write-Warning \'No vulnerabilities found and continuing to build it.\'
					}

					Write-Host "Finished SAST file scanning."
					
					if(Test-Path -Path $destinationPath -PathType Leaf)
					{
					    Remove-Item $destinationPath
					}
					'''
            }
        }
		stage('build') {
            steps {
                sh 'make' 
                archiveArtifacts artifacts: '**/target/*.jar', fingerprint: true 
            }
        }
    }
}
