$computername = $env:computername
#$OSVersion = [Environment]::OSVersion.Version
#https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx

$ver = ((Get-CimInstance Win32_OperatingSystem).version).split(".")
$OSVersion = New-Object -TypeName PSObject -Property (@{'Major' = $ver[0]; 'Minor' = $ver[1]; 'Build' = $ver[2]; 'Revision' = '0';})
$StdOutFileName ="c:\temp\stdout.txt"

cd c:\temp
Get-Date | out-file $StdOutFileName -append -Force

#################################
#
#  SDP functions
#
#

function FirstTimeExecution {write-host "FirstTimeExecution"}
function EndDataCollection{write-host "EndDataCollection"}
$ScriptExecutionInfo_Summary = New-Object PSObject
$DiagProcesses=New-Object System.Collections.ArrayList
$DiagProcessesFileDescription=@{}
$DiagProcessesSectionDescription=@{}
$DiagProcessesFilesToCollect=@{}
$DiagProcessesVerbosity=@{}
$DiagProcessesAddFileExtension=@{}
$DiagProcessesBGProcessTimeout=@{}
$DiagProcessesRenameOutput=@{}
$DiagProcessesScriptblocks=@{}
$DiagProcessesSkipMaxParallelDiagCheck=@{}
$DiagProcessesSessionNames=@{}
$global:DiagCachedCredentials=@{}

$MaxParallelDiagProcesses=$null
$computername = $env:computername




# The function below is used to build the global variable $OSArchitecture.
# You can use the $OSArchitecture to define the computer architecture. Current Values are:
# X86 - 32-bit
# AMD64 - 64-bit
# IA64 - 64-bit

Function Get-ComputerArchitecture() 
{ 
	if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
	{ 
		return $Env:PROCESSOR_ARCHITEW6432 
	} 
	else 
	{ 
		return $Env:PROCESSOR_ARCHITECTURE 
	}
}

$OSArchitecture = Get-ComputerArchitecture




function RegQuery(
	$RegistryKeys,
    [string] $OutputFile,
    [string] $fileDescription,
	[string] $sectionDescription="",
    [boolean] $Recursive = $False,
    [boolean] $AddFileToReport = $true,
	[boolean] $Query = $true,
	[boolean] $Export = $false
    )
{

# RegQuery function
# ---------------------
# Description:
#       This function uses reg.exe to export a registry key to a text file. Adding the file to the report.
# 
# Arguments:
#       RegistryKeys: One or more registry keys to be exported (Example: "HKLM\Software\Microsoft\Windows NT")
#		OutputFile: Name of output file. If -Query is $true, you should use a .txt extension. This command will switch it to .reg automatically for -Export $true.
#		fileDescription: Individual description of the Registry Key in the report
#		Recursive: If $true, resulting file contains key and subkeys.
#		sectionDescription: Name of the section (Optional - Default: "Registry Information (Text format)")
#       AddFileToReport: if $true, the resulting output will be added to report and a reference to it will be created on report xml (Default=$true)
# 
#Example:
#		RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT" -OutputFile "$Computername_WinNT.TXT" -fileDescription "Windows NT Reg Key" -sectionDescription "Software Registry keys"
# 

	if ([string]::IsNullOrEmpty($sectionDescription))
	{
		$sectionDescription="Registry Information (Text format)"
	}

	if($debug -eq $true){"Run RegQuery function. `r`n RegistryKeys: $RegistryKeys `r`n OutputFile: $OutputFile `r`n AddFileToReport = $AddFileToReport" | WriteTo-StdOut -DebugOnly}
	$RegKeyExist = $false
	if(($Query -eq $false) -and ($Export -eq $false)){"Either -Query or -Export must be set to `$true" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation; throw}
	ForEach ($RegKey in $RegistryKeys) {
		$RegKeyString = $UtilsCTSStrings.ID_RegistryKeys
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
		$PSRegKey=$RegKey -replace "HKLM\\", "HKLM:\" -replace "HKCU\\", "HKCU:\" -replace "HKU\\", "Registry::HKEY_USERS\"
		
		if (Test-Path $PSRegKey) 
		{
			$RegKeyExist = $true			
			$PSRegKeyObj = Get-Item ($PSRegKey)
			
			if ($PSRegKeyObj -ne $null) 
			{
				$RegExeRegKey = ($PSRegKeyObj.Name -replace "HKEY_USERS\\", "HKU\") -replace "HKEY_LOCAL_MACHINE\\", "HKLM\" -replace "HKEY_CURRENT_USER\\", "HKCU\" -replace "HKEY_CLASSES_ROOT\\", "HKCR\"	
			}
			else 
			{
				$RegExeRegKey = ($RegExeRegKey -replace "HKEY_USERS\\", "HKU\\") -replace "HKEY_LOCAL_MACHINE\\", "HKLM\" -replace "HKEY_CURRENT_USER\\", "HKCU\" -replace "HKEY_CLASSES_ROOT\\", "HKCR\"
			}
			
			if($Export)
			{
				$tmpFile = [System.IO.Path]::GetTempFileName()
				$OutputFile2 = $OutputFile
				if([System.IO.Path]::GetExtension($OutputFile2) -ne ".reg")
				{
					$OutputFile2 = $OutputFile2.Substring(0,$OutputFile2.LastIndexOf(".")) + ".reg"
				}
				$CommandToExecute = "reg.exe EXPORT `"$RegExeRegKey`" `"$tmpFile`" /y" 
				$X = RunCmd -commandToRun $CommandToExecute -collectFiles $false -useSystemDiagnosticsObject
				[System.IO.StreamReader]$fileStream = [System.IO.File]::OpenText($tmpFile)
				if([System.IO.File]::Exists($OutputFile2))
				{
					#if the file already exists, we assume it has the header at the top, so we'll strip those lines off
					$fileStream.ReadLine() | Out-Null 
					$fileStream.ReadLine() | Out-Null 
				}
				$fileStream.ReadToEnd() | Out-File $OutputFile2 -Append 
				$fileStream.Close()
				Remove-Item $tmpFile -ErrorAction SilentlyContinue | Out-Null 
			}
			
			if($Query)
			{
				$CommandToExecute = "reg.exe query `"$RegExeRegKey`""
				if ($Recursive -eq $true) {
					$CommandToExecute = "$CommandToExecute /s"
				}
				
				$CommandToExecute = "$CommandToExecute >> `"$OutputFile`""
				
				"-" * ($RegKey.Length +2) + "`r`n[$RegKey]`r`n" + "-" * ($RegKey.Length +2) | Out-File -FilePath $OutputFile -Append -Encoding Default

				$X = RunCmD -commandToRun $CommandToExecute -collectFiles $false -useSystemDiagnosticsObject
			}
		} 
		else 
		{
			"The registry key $RegKey does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
		}
		
	}
			
	if ($RegKeyExist -eq $true) 
	{ 
		if ($AddFileToReport -eq $true) 
		{
			if($Query) {Update-DiagReport -Id $sectionDescription -Name $fileDescription -File $OutputFile}
			if($Export){Update-DiagReport -Id $sectionDescription -Name $fileDescription -File $OutputFile2}
		}
	}
}

function RegQueryValue(
	$RegistryKeys,
	$RegistryValues,
	[string] $sectionDescription,
    [string] $OutputFile,
    [string] $fileDescription,
    [boolean] $CollectResultingFile = $True
    )
{
	
	if ([string]::IsNullOrEmpty($sectionDescription))
	{
		$sectionDescription="Registry Information (Text format)"
	}

	if($debug -eq $true){"RegQueryValue:`r`n RegistryKeys: $RegistryKeys `r`n OutputFile: $OutputFile `r`n CollectResultingFile = $CollectResultingFile" | WriteTo-StdOut -DebugOnly}
	$ErrorActionPreference = "SilentlyContinue"
	$RegValueExist = $false
	$CurrentMember = 0
	ForEach ($RegKey in $RegistryKeys) 
	{
	
		$RegKeyString = $UtilsCTSStrings.ID_RegistryValue
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	
		$PSRegKey=$RegKey -replace "HKLM\\", "HKLM:\" 
		$PSRegKey=$PSRegKey -replace "HKCU\\", "HKCU:\"
		if (Test-Path $PSRegKey) {
			$testRegValue = $null
			if ($RegistryValues -is [array]) 
			{
				$RegValue = $RegistryValues[$CurrentMember]
			} else {
				$RegValue = $RegistryValues
			}
			#Test if registry value exists
			$testRegValue = get-itemproperty -name $RegValue -Path $PSRegKey
			if ($testRegValue -ne $null) {
				$RegValueExist = $true
				$CommandToExecute = "$Env:COMSPEC /C reg.exe query `"$RegKey`" /v `"$RegValue`""
				
				$CommandToExecute = "$CommandToExecute >> `"$OutputFile`""
				$RegKeyLen = $RegKey.Length + $RegValue.Length + 3
				"-" * ($RegKeyLen) + "`r`n[$RegKey\$RegValue]`r`n" + "-" * ($RegKeyLen) | Out-File -FilePath $OutputFile -Append
	
				RunCmD -commandToRun $CommandToExecute -collectFiles $false
			} else {
				"        The registry value $RegKey\$RegValue does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
			}
		$CurrentMember = $CurrentMember +1			
		} else {
			"        The registry key $RegKey does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
		}
	
	}
			
	if ($RegValueExist-eq $true) 
	{ 
		if ($CollectResultingFile -eq $true) {
			Update-DiagReport -Id $sectionDescription -Name $fileDescription -File $OutputFile
		}
	}
}

#Function RegSave
#----------------
#This function saves a registry key to a registry hive file using reg.exe utility

function RegSave(
	$RegistryKeys,
	[string] $sectionDescription,
    [string] $OutputFile,
    [string] $fileDescription
    )
{

	if ([string]::IsNullOrEmpty($sectionDescription))
	{
		$sectionDescription="Registry Information (Hive format)"
	}

	if($debug -eq $true){"Run RegSave function. `r`n RegistryKeys: $RegistryKeys `r`n OutputFile: $OutputFile `r`n fileDescription: $fileDescription" | WriteTo-StdOut -DebugOnly}
	$ErrorActionPreference = "SilentlyContinue"
	$RegValueExist = $false
	$CurrentMember = 0
	ForEach ($RegKey in $RegistryKeys) {
	
		$RegKeyString = $UtilsCTSStrings.ID_Hive
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	
		$PSRegKey=$RegKey -replace "HKLM\\", "HKLM:\" 
		$PSRegKey=$PSRegKey -replace "HKCU\\", "HKCU:\"
		if (Test-Path $PSRegKey) {
			$CommandToExecute = "$Env:windir\system32\reg.exe save `"$RegKey`" `"$OutputFile`" /y"
			
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
		} else {
			"[RegSave] The registry key $RegKey does not exist" | WriteTo-StdOut -ShortFormat -Color 'DarkYellow' -InvokeInfo $MyInvocation
		}
		
	}		
}

Function Collect-DiscoveryFiles
{
	$DiscoveryExecutionLog = Join-Path $PWD.Path ($ComputerName + '_DiscoveryExecutionLog.log')
	if (test-path ($DiscoveryExecutionLog))
	{
		Get-Content -Path ($DiscoveryExecutionLog) | WriteTo-StdOut
	}
	else
	{
		"[Collect-DiscoveryFiles] Discovery execution log could not be found at $DiscoveryExecutionLog" | WriteTo-StdOut -ShortFormat
	}
	
	$DiscoveryReport = "$($Computername)_DiscoveryReport.xml"
	
	Collectfiles -filesToCollect $DiscoveryReport  -fileDescription "Config Explorer Discovery Report" -sectionDescription "Config Explorer Files" -Verbosity "Debug"
	Collectfiles -filesToCollect "$($Computername)_DiscoveryDebugLog.xml" -fileDescription "Config Explorer Debug" -sectionDescription "Config Explorer Files" -Verbosity "Debug"

	# Disabling convertion to HTML for now until more meaningful information to be processed
	
#	if ((Test-path $DiscoveryReport) -and (Test-Path 'ConfigExplorerClientView.xslt'))
#	{
#		#Convert XML to HTML	
#		$HTMLFilename = Join-Path $PWD.Path "$($Computername)_DiscoveryReport.htm"
#		[xml] $XSLContent = Get-Content 'ConfigExplorerClientView.xslt'
#
#		$XSLObject = New-Object System.Xml.Xsl.XslTransform
#		$XSLObject.Load($XSLContent)
#		$XSLObject.Transform($DiscoveryReport, $HTMLFilename)
#	    
#		#Remove-Item $XMLFilename
#		"DiscoveryReport converted to " + (Split-Path $HTMLFilename -Leaf) | WriteTo-StdOut -ShortFormat
#		
#		Collectfiles -filesToCollect $HTMLFilename -fileDescription "Configuration Information Report" -sectionDescription "Config Explorer Files"
#		
#	}
}

function RegQueryValue(
	$RegistryKeys,
	$RegistryValues,
	[string] $sectionDescription,
    [string] $OutputFile,
    [string] $fileDescription,
    [boolean] $CollectResultingFile = $True
    )
{
	
	if ([string]::IsNullOrEmpty($sectionDescription))
	{
		$sectionDescription="Registry Information (Text format)"
	}

	if($debug -eq $true){"RegQueryValue:`r`n RegistryKeys: $RegistryKeys `r`n OutputFile: $OutputFile `r`n CollectResultingFile = $CollectResultingFile" | WriteTo-StdOut -DebugOnly}
	$ErrorActionPreference = "SilentlyContinue"
	$RegValueExist = $false
	$CurrentMember = 0
	ForEach ($RegKey in $RegistryKeys) 
	{
	
		$RegKeyString = $UtilsCTSStrings.ID_RegistryValue
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	
		$PSRegKey=$RegKey -replace "HKLM\\", "HKLM:\" 
		$PSRegKey=$PSRegKey -replace "HKCU\\", "HKCU:\"
		if (Test-Path $PSRegKey) {
			$testRegValue = $null
			if ($RegistryValues -is [array]) 
			{
				$RegValue = $RegistryValues[$CurrentMember]
			} else {
				$RegValue = $RegistryValues
			}
			#Test if registry value exists
			$testRegValue = get-itemproperty -name $RegValue -Path $PSRegKey
			if ($testRegValue -ne $null) {
				$RegValueExist = $true
				$CommandToExecute = "$Env:COMSPEC /C reg.exe query `"$RegKey`" /v `"$RegValue`""
				
				$CommandToExecute = "$CommandToExecute >> `"$OutputFile`""
				$RegKeyLen = $RegKey.Length + $RegValue.Length + 3
				"-" * ($RegKeyLen) + "`r`n[$RegKey\$RegValue]`r`n" + "-" * ($RegKeyLen) | Out-File -FilePath $OutputFile -Append
	
				RunCmD -commandToRun $CommandToExecute -collectFiles $false
			} else {
				"        The registry value $RegKey\$RegValue does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
			}
		$CurrentMember = $CurrentMember +1			
		} else {
			"        The registry key $RegKey does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
		}
	
	}
			
	if ($RegValueExist-eq $true) 
	{ 
		if ($CollectResultingFile -eq $true) {
			Update-DiagReport -Id $sectionDescription -Name $fileDescription -File $OutputFile
		}
	}
}

#Function RegSave
#----------------
#This function saves a registry key to a registry hive file using reg.exe utility

function RegSave(
	$RegistryKeys,
	[string] $sectionDescription,
    [string] $OutputFile,
    [string] $fileDescription
    )
{

	if ([string]::IsNullOrEmpty($sectionDescription))
	{
		$sectionDescription="Registry Information (Hive format)"
	}

	if($debug -eq $true){"Run RegSave function. `r`n RegistryKeys: $RegistryKeys `r`n OutputFile: $OutputFile `r`n fileDescription: $fileDescription" | WriteTo-StdOut -DebugOnly}
	$ErrorActionPreference = "SilentlyContinue"
	$RegValueExist = $false
	$CurrentMember = 0
	ForEach ($RegKey in $RegistryKeys) {
	
		$RegKeyString = $UtilsCTSStrings.ID_Hive
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	
		$PSRegKey=$RegKey -replace "HKLM\\", "HKLM:\" 
		$PSRegKey=$PSRegKey -replace "HKCU\\", "HKCU:\"
		if (Test-Path $PSRegKey) {
			$CommandToExecute = "$Env:windir\system32\reg.exe save `"$RegKey`" `"$OutputFile`" /y"
			
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
		} else {
			"[RegSave] The registry key $RegKey does not exist" | WriteTo-StdOut -ShortFormat -Color 'DarkYellow' -InvokeInfo $MyInvocation
		}
		
	}		
}


Function BackgroundProcessCreate([string]$ProcessName, 
								[string]$Arguments,
								$filesToCollect, 
								[string]$fileDescription="", 
								[string]$sectionDescription="", 
								[string]$Verbosity="Informational",
								[switch]$noFileExtensionsOnDescription,
								[boolean]$renameOutput = $true,
								[boolean]$CollectFiles = $true,
								[int] $TimeoutMinutes = 15,
								[scriptblock]$PostProcessingScriptBlock,
								[switch] $SkipMaxParallelDiagCheck,
								[string] $SessionName = 'Default')
{
	if ($MaxParallelDiagProcesses -eq $null)
	{
		#$MaxParallelDiagProcesses = Get-MaxBackgroundProcesses
		Set-Variable -Name MaxParallelDiagProcesses -Value (Get-MaxBackgroundProcesses)
	}
	
	#Wait until there are slots available
	"[BackgroundProcessCreate] Creating background process: [(Session: " + $SessionName+ ") Process: `'" + $ProcessName + "`' - Arguments: `'" + $Arguments + "`']" | WriteTo-StdOut
	$WaitMSG = $false

	if ($SkipMaxParallelDiagCheck.IsPresent -eq $false)
	{
		WaitForBackgroundProcesses -MaxBackgroundProcess $MaxParallelDiagProcesses
	}
	else
	{
		#When SkipMaxParallelDiagCheck is used, increase the number of allowed background processes by 1 while the new process is running
		if ($Global:OverrideMaxBackgroundProcesses -eq $null)
		{
			$Global:OverrideMaxBackgroundProcesses = $MaxParallelDiagProcesses
		}
		$Global:OverrideMaxBackgroundProcesses++
		Set-MaxBackgroundProcesses -NumberOfProcesses $Global:OverrideMaxBackgroundProcesses
	}
	
	#Start process in background
	$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments 

	#Fill out Diagnostic variables so we can use in the future
	[Void] $DiagProcesses.Add($Process)
	$DiagProcessesFileDescription.Add($Process.Id, $fileDescription)
	$DiagProcessesSectionDescription.Add($Process.Id, $sectionDescription)
	$DiagProcessesVerbosity.Add($Process.Id, $Verbosity)
	$DiagProcessesFilesToCollect.Add($Process.Id, $filesToCollect)
	$DiagProcessesAddFileExtension.Add($Process.Id, -not ($noFileExtensionsOnDescription.IsPresent))
	$DiagProcessesBGProcessTimeout.Add($Process.Id, $TimeoutMinutes)
	$DiagProcessesSessionNames.Add($Process.Id, $SessionName)
	if ($SkipMaxParallelDiagCheck.IsPresent)
	{
		$DiagProcessesSkipMaxParallelDiagCheck.Add($Process.Id, $true)
	}

	if($null -ne $PostProcessingScriptBlock)
	{
		if($Process.HasExited)
		{
			"[BackgroundProcessCreate] Process already exited. Running `$PostProcessingScriptBlock" | WriteTo-StdOut -shortformat
			& $PostProcessingScriptBlock
		}
		else
		{
			if((test-path variable:psversiontable) -and ($PSVersionTable.PSVersion.Major -ge 2))
			{
				$Process.EnableRaisingEvents = $true
				$postProcSB = @"
				. .\utils_cts.ps1
				"[Utils_CTS] Running PostProcessingScriptBlock" | WriteTo-StdOut -ShortFormat
				$($PostProcessingScriptBlock.ToString())
"@
				"[BackgroundProcessCreate] Registering an event for process exit and attaching script block. ScriptBlock = `r`n $postProcSB" | WriteTo-StdOut -ShortFormat
				
				$ModifiedSB = [Scriptblock]::Create($postProcSB);
				Register-ObjectEvent -InputObject $Process -EventName "Exited" -Action $ModifiedSB -SourceIdentifier $Process.Id			
			}
			else
			{
				$DiagProcessesScriptblocks.Add($Process.Id, $PostProcessingScriptBlock)
			}
		}
	}
	$DiagProcessesRenameOutput.Add($Process.Id, $renameOutput)
	
	Return $Process
	
}
Function Set-MaxBackgroundProcesses
{
	param([int]$NumberOfProcesses=2,[switch]$Default)
	if($Default)
	{
		"Set-MaxBackgroundProcesses called with -Default" | WriteTo-StdOut -ShortFormat
		Remove-Variable "OverrideMaxBackgroundProcesses" -Scope Global -ErrorAction SilentlyContinue
	}
	else
	{
		"Set-MaxBackgroundProcesses called with NumberOfProcesses = $NumberOfProcesses" | WriteTo-StdOut -ShortFormat
		Set-Variable "OverrideMaxBackgroundProcesses" -Scope Global -Value $NumberOfProcesses
	}
}


Function Get-MaxBackgroundProcesses
{
	$overrideVal = 0
	if(($global:OverrideMaxBackgroundProcesses -ne $null) -and ($global:OverrideMaxBackgroundProcesses -is [int]))
	{
		$overrideVal = [Math]::Abs(($global:OverrideMaxBackgroundProcesses -as [int]))
	}
	$Win32CS = Get-WmiObject -Class Win32_ComputerSystem
	#Pre-WinVista do not support NumberOfLogicalProcessors:
	$NumberOfCores = $Win32CS.NumberOfLogicalProcessors
	
	if ($NumberOfCores -eq $null)
	{
		$NumberOfCores = $Win32CS.NumberOfProcessors
	}
	
	return [Math]::Max($NumberOfCores,$overrideVal)
}



Function Run-ExternalPSScript([string]$ScriptPath,  
				$filesToCollect = "", 
				[string]$fileDescription="", 
				[string]$sectionDescription="", 
				[boolean]$collectFiles=$false,
				[string]$Verbosity="Informational",
				[switch]$BackgroundExecution,
				[string]$BackgroundExecutionSessionName = 'Default',
				[int] $BackgroundExecutionTimeOut = 15,
				[switch] $BackgroundExecutionSkipMaxParallelDiagCheck,
				[scriptblock] $BackgroundExecutionPostProcessingScriptBlock)
{

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[RunExternalPSScript (ScriptPath = $ScriptPath) (filesToCollect: $filesToCollect) (fileDescription: $fileDescription) (sectionDescription: $sectionDescription) (collectFiles $collectFiles)]" -InvokeInfo $MyInvocation
		$Error.Clear()
		continue
	}

	if ($BackgroundExecution.IsPresent)
	{
		$StringToAdd += " (Background Execution)"
	}
	
	$StringToAdd += " (Collect Files: $collectFiles)"
	
	if ($collectFiles -and ([string]::IsNullOrEmpty($fileDescription) -or [string]::IsNullOrEmpty($sectionDescription) -or [string]::IsNullOrEmpty($filesToCollect)))
	{
		"[RunExternalPSScript] ERROR: -CollectFiles argument is set to $true but a fileDescription, sectionDescription and/or filesToCollect were not specified`r`n   fileDescription: [$fileDescription]`r`n   sectionDescription: [$sectionDescription]`r`n   filesToCollect: [$filesToCollect]" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation
	}
	
	"[RunExternalPSScript] Running External PowerShell Script: $ScriptPath $ScriptArgumentCmdLine " + $StringToAdd | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat

	$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
	if (Test-Path $ScriptPath)
	{
		if ((test-path variable:\psversiontable) -and ($OSVersion.Major -gt 5))
		{
			# PowerShell 2.0+/ WinVista+
			$DisablePSExecutionPolicy = "`$context = `$ExecutionContext.GetType().GetField(`'_context`',`'nonpublic,instance`').GetValue(`$ExecutionContext); `$authMgr = `$context.GetType().GetField(`'_authorizationManager`',`'nonpublic,instance`'); `$authMgr.SetValue(`$context, (New-Object System.Management.Automation.AuthorizationManager `'Microsoft.PowerShell`'))"
			$PSArgumentCmdLine = "-command `"& { $DisablePSExecutionPolicy ;" + $ScriptPath + " $ScriptArgumentCmdLine}`""
		}
		else
		{
			# PowerShell 1.0 ($psversiontable variable does not exist in PS 1.0)
			$PSArgumentCmdLine = "-command `"& { invoke-expression (get-content `'" + $ScriptPath + "`'| out-string) }`""
		}
		
		if ($BackgroundExecution.IsPresent -eq $false)
		{	
			$process = ProcessCreate -Process "powershell.exe" -Arguments $PSArgumentCmdLine
			
			"PowerShell started with Process ID $($process.Id)" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
			"--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
			$process.WaitForExit()
			$StdoutOutput = $process.StandardOutput.ReadToEnd() 
			if ($StdoutOutput -ne $null)
			{
				($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			else
			{
				'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			$ProcessExitCode = $process.ExitCode
			
			if (($ProcessExitCode -ne 0) -or ($process.StandardError.EndOfStream -eq $false))
			{
				"[RunExternalPSScript] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode)  + " when running $ScriptPath"| WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
				$ProcessStdError = $process.StandardError.ReadToEnd()
				if ($ProcessStdError -ne $null)
				{
					"--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
				}
			}
			"--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat	
			
			if ($collectFiles -eq $true) 
			{	
				"[RunExternalPSScript] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
			}
			return $ProcessExitCode
		} 
		else 
		{ 
			$Process = BackgroundProcessCreate -ProcessName "powershell.exe" -Arguments $PSArgumentCmdLine -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -TimeoutMinutes $BackgroundExecutionTimeOut -PostProcessingScriptBlock $BackgroundExecutionPostProcessingScriptBlock -SkipMaxParallelDiagCheck:$BackgroundExecutionSkipMaxParallelDiagCheck -SessionName $BackgroundExecutionSessionName
			return $Process
		}
	}
	else
	{
		"[RunExternalPSScript] ERROR: Script [$ScriptPath] could not be found" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation
	}
}




Function ProcessCreate($Process, $Arguments = "", $WorkingDirectory = $null)
{
	
	"ProcessCreate($Process, $Arguments) called." | WriteTo-StdOut -ShortFormat -DebugOnly
	
	$Error.Clear()
	$processStartInfo  = new-object System.Diagnostics.ProcessStartInfo
	$processStartInfo.fileName = $Process
	if ($Arguments.Length -ne 0) { $processStartInfo.Arguments = $Arguments }
	if ($WorkingDirectory -eq $null) {$processStartInfo.WorkingDirectory = (Get-Location).Path}
	$processStartInfo.UseShellExecute = $false
	$processStartInfo.RedirectStandardOutput = $true
	$processStartInfo.REdirectStandardError = $true
	
	#$process = New-Object System.Diagnostics.Process
	#$process.startInfo=$processStartInfo
	
	$process = [System.Diagnostics.Process]::Start($processStartInfo)
	
	if ($Error.Count -gt 0)
	{
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$PositionMessage = $Error[0].InvocationInfo.PositionMessage
		"[ProcessCreate] Error " + $errorCode + " on: " + $line + ": $errorMessage" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation

		$Error.Clear()
	}

	Return $process
}


function runcmd {
		Param(		[string]$commandToRun, 
				$filesToCollect = $null, 
				[string]$fileDescription="", 
				[string]$sectionDescription="", 
				[boolean]$collectFiles=$true,
				[switch]$useSystemDiagnosticsObject,
				[string]$Verbosity="Informational",
				[switch]$NoFileExtensionsOnDescription,
				[switch]$BackgroundExecution,
				[boolean]$RenameOutput=$false,
				[switch]$DirectCommand,
				[Scriptblock] $PostProcessingScriptBlock)


"[RunCMD] Running Command" + $StringToAdd + ":`r`n `r`n                      $commandToRun`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat

	# A note: if CollectFiles is set to False, background processing is not allowed
	# This is to avoid problems where multiple background commands write to the same file
	if (($BackgroundExecution.IsPresent -eq $false) -or ($collectFiles -eq $false))
	{	
		"--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
		
		if ($useSystemDiagnosticsObject.IsPresent) 
		{
			if ($DirectCommand.IsPresent)
			{
				if ($commandToRun.StartsWith("`""))
				{
					$ProcessName = $commandToRun.Split("`"")[1]
					$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
				} 
				elseif ($commandToRun.Contains(".exe"))
				# 2. No quote found - try to find a .exe on $commandToRun
				{
					$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
					$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
				}
				else
				{
					$ProcessName = "cmd.exe" 
					$Arguments = "/c `"" + $commandToRun + "`""
				}
				$process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			}
			else
			{
				$process = ProcessCreate -Process "cmd.exe" -Arguments ("/s /c `"" + $commandToRun + "`"")
			}
			$process.WaitForExit()
			$StdoutOutput = $process.StandardOutput.ReadToEnd() 
			if ($StdoutOutput -ne $null)
			{
				($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			else
			{
				'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			$ProcessExitCode = $process.ExitCode
			if ($ProcessExitCode -ne 0) 
			{
				"[RunCMD] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode)  + " when running command line:`r`n             " + $commandToRun | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
				$ProcessStdError = $process.StandardError.ReadToEnd()
				if ($ProcessStdError -ne $null)
				{
					"--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
				}
			}
		} 
		else 
		{
			if ($commandToRun -ne $null)
			{
				$StdoutOutput = Invoke-Expression $commandToRun
				if ($StdoutOutput -ne $null)
				{
					($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
				}
				else
				{
					'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
				}
				$ProcessExitCode = $LastExitCode
				if ($LastExitCode -gt 0)
				{
					"[RunCMD] Warning: Process exited with error code " + ("0x{0:X}" -f $ProcessExitCode) | writeto-stdout -InvokeInfo $MyInvocation -Color 'DarkYellow'
				}
			}
			else
			{
				'[RunCMD] Error: a null -commandToRun argument was sent to RunCMD' | writeto-stdout -InvokeInfo $MyInvocation -IsError
				$ProcessExitCode = 99
			}
		}
		
		"--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat
		
		if ($collectFiles -eq $true) 
		{	
			"[RunCMD] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
			if ($noFileExtensionsOnDescription.isPresent)
			{
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -noFileExtensionsOnDescription -renameOutput $renameOutput -InvokeInfo $MyInvocation
			} else {
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
			}
		}
		#RunCMD returns exit code only if -UseSystemDiagnosticsObject is used
		if ($useSystemDiagnosticsObject.IsPresent)
		{
			return $ProcessExitCode
		}
	} 
	else 
	{ 	#Background Process
		# Need to separate process name from $commandToRun:
		# 1. Try to identify a quote:
		if ($commandToRun.StartsWith("`""))
		{
			$ProcessName = $commandToRun.Split("`"")[1]
			$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
		} 
		elseif ($commandToRun.Contains(".exe"))
		# 2. No quote found - try to find a .exe on $commandToRun
		{
			$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
			$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
		}
		else
		{
			$ProcessName = "cmd.exe" 
			$Arguments = "/c `"" + $commandToRun + "`""
		}
		if ($noFileExtensionsOnDescription.isPresent)
		{
			$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -CollectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock 
		}
		else 
		{
			$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -noFileExtensionsOnDescription -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock
	}
	}
}

$global:DebugOutLog = "$pwd\stdout.log"
if($null -eq $global:m_WriteCriticalSection) {$global:m_WriteCriticalSection = New-Object System.Object}
function WriteTo-StdOut {
	Param ( 
		[Parameter(ValueFromPipeline=$True)]$ObjectToAdd,
		[switch]$ShortFormat,
		[switch]$IsError,
		$Color ="Yellow",
		[switch]$DebugOnly,
		[switch]$PassThru,
		[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation,
		[string]$AdditionalFileName = $null,
		[switch]$noHeader
        
	)
  
  
   	BEGIN{
		$WhatToWrite = @()
        
		if ($ObjectToAdd -ne  $null)
		{
			$WhatToWrite  += $ObjectToAdd

		} 
		
		if( ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host"))
		{
			if($Color -eq $null)
			{
				$Color = $Host.UI.RawUI.ForegroundColor
			}
			elseif($Color -isnot [ConsoleColor])
			{
				$Color = [Enum]::Parse([ConsoleColor],$Color)
			}
			$scriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
		}
		
		$ShortFormat = $ShortFormat -or $global:ForceShortFormat
	}
	PROCESS
	{
		if ($_ -ne $null)
		{
			if ($_.GetType().Name -ne "FormatEndData") 
			{
				$WhatToWrite += $_ | Out-String 
			}
			else 
			{
				$WhatToWrite = "Object not correctly formatted. The object of type Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData is not valid or not in the correct sequence."
			}
		}
	}
	END	{
		if($ShortFormat)
		{
			$separator = " "
		}
		else
		{
			$separator = "`r`n"
		}
		$WhatToWrite = [string]::Join($separator,$WhatToWrite)
		while($WhatToWrite.EndsWith("`r`n"))
		{
			$WhatToWrite = $WhatToWrite.Substring(0,$WhatToWrite.Length-2)
		}
		if( ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host"))
		{
			$output = "[$([DateTime]::Now.ToString(`"s`"))] [$($scriptName):$($MyInvocation.ScriptLineNumber)]: $WhatToWrite"

			if($IsError.Ispresent)
			{
				$Host.UI.WriteErrorLine($output)
			}
			else
			{
				if($Color -eq $null){$Color = $Host.UI.RawUI.ForegroundColor}
				$output | Write-Host -ForegroundColor $Color
			}
			if($global:DebugOutLog -eq $null)
			{
				$global:DebugOutLog = Join-Path $Env:TEMP "$([Guid]::NewGuid().ToString(`"n`")).txt"
			}
			$output | Out-File -FilePath $global:DebugOutLog -Append -Force 
		}
		elseif(-not $DebugOnly)
		{
			[System.Threading.Monitor]::Enter($global:m_WriteCriticalSection)
			
			trap [Exception] 
			{
				WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
				continue
			}
			Trap [System.IO.IOException]
			{
				# An exection in this location indicates either that the file is in-use or user do not have permissions. Wait .5 seconds. Try again
				sleep -Milliseconds 500
				WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
				continue
			}
			
			if($ShortFormat)
			{
				if ($NoHeader.IsPresent)
				{
				    $WhatToWrite | Out-File -FilePath $StdOutFileName -append # -ErrorAction SilentlyContinue 
					 if ($AdditionalFileName.Length -gt 0)
					 {
					 	$WhatToWrite | Out-File -FilePath $AdditionalFileName -append # -ErrorAction SilentlyContinue 
					 }
				}
				else
				{
		             "[" + (Get-Date -Format "T") + " " + $ComputerName + " - " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " - " + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
					 if ($AdditionalFileName.Length -gt 0)
					 {
					 	"[" + (Get-Date -Format "T") + " " + $ComputerName + " - " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " - " + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
					 }
				}
			}
			else
			{
				if ($NoHeader.IsPresent)
				{
	                 "`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName -append # -ErrorAction SilentlyContinue 
					 if ($AdditionalFileName.Length -gt 0)
					 {
					 	"`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append  #-ErrorAction SilentlyContinue 
					 }
				}
				else
				{
	                 "`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName # -append -ErrorAction SilentlyContinue 
					 if ($AdditionalFileName.Length -gt 0)
					 {
					 	"`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append # -ErrorAction SilentlyContinue 
					 }
				}
			}
			[System.Threading.Monitor]::Exit($global:m_WriteCriticalSection)

		}
		if($PassThru)
		{
			return $WhatToWrite
		}
	}
}

    


	


function Write-GenericMessage ([string] $RootCauseID = $null,
		$SolutionTitle = $null,
		$InternalContentURL = $null,
		$PublicContentURL = $null,
		$ProcessName = $null,
		$Component = $null,
		$ModulePath = $null,
		$Verbosity = "Informational",
		$sectionDescription = "Additional Information",
		$AdditionalSDPOnlyInformation = $null,
		$SDPFileReference = $null,
		$InformationCollected = $null,
		$Fixed = $null,
		[int] $Visibility = 3,
		[int] $SupportTopicsID = 0,
		[int] $MessageVersion = 0)
{
			$MSG = New-Object PSObject
			$MSG | Add-Member -membertype noteproperty -name 'RootCauseID' -value $RootCauseID
			$MSG | Add-Member -membertype noteproperty -name 'SolutionTitle' -value $SolutionTitle
			$MSG | Add-Member -membertype noteproperty -name 'InternalContentURL' -value $InternalContentURL
			$MSG | Add-Member -membertype noteproperty -name 'PublicContentURL' -value $PublicContentURL
			$MSG | Add-Member -membertype noteproperty -name 'ProcessName' -value $ProcessName
			$MSG | Add-Member -membertype noteproperty -name 'Component' -value $Component
			$MSG | Add-Member -membertype noteproperty -name 'ModulePath' -value $ModulePath
			$MSG | Add-Member -membertype noteproperty -name 'Verbosity' -value $Verbosity
			$MSG | Add-Member -membertype noteproperty -name 'Fixed' -value $Fixed
			$MSG | Add-Member -membertype noteproperty -name 'Visibility' -value $Visibility
			$MSG | Add-Member -membertype noteproperty -name 'SupportTopicsID' -value $SupportTopicsID
			$MSG | Add-Member -membertype noteproperty -name 'Culture' -value $Culture
			$MSG | Add-Member -membertype noteproperty -name 'MessageVersion' -value $MessageVersion
			$MSG | Add-Member -membertype noteproperty -name '[SDP] SectionDescription' -value $sectionDescription
			$MSG | Add-Member -membertype noteproperty -name '[SDP] AdditionalSDPOnlyInformation' -value $AdditionalSDPOnlyInformation
			$MSG | Add-Member -membertype noteproperty -name '[SDP] SDPFileReference' -value $SDPFileReference
			$MSG | Add-Member -membertype noteproperty -name 'InformationCollected' -value ($InformationCollected | fl | Out-String)
			"Write-GenericMessage called: " + ($MSG | fl | Out-String) | WriteTo-StdOut -DebugOnly -Color DarkYellow  -InvokeInfo $MyInvocation
}


if (!(Get-alias Update-DiagRootCause -ErrorAction SilentlyContinue)) { New-Alias -Name Update-DiagRootCause -Value Write-Host }
if (!(Get-alias dri -ErrorAction SilentlyContinue)) { New-Alias -Name dri -Value dir }
if (!(Get-alias whaomi -ErrorAction SilentlyContinue)) { New-Alias -Name whaomi -Value whoami }

function CollectFiles($filesToCollect, 
				[string]$fileDescription="File", 
				[string]$sectionDescription="Section",
				[boolean]$renameOutput=$false,
				[string]$MachineNamePrefix=$ComputerName,
				[switch]$noFileExtensionsOnDescription,
				[string]$Verbosity="Informational",
				[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation)
 {
	"Collecting filesToCollect = $filesToCollect fileDescription = $fileDescription sectionDescription = $sectionDescription renameOutput = $renameOutput" + $args | write-host -foregroundcolor "Magenta"
}

function Write-DiagProgress {
    	if ($args) { $args | write-host  -foregroundcolor "yellow"}
	$input | write-host  -foregroundcolor "yellow"
	}

function Get-DiagInput {
	write-diagprogress "$args"
	pause
}

function WriteTo-ErrorDebugReport {
	Param ( [switch] $ErrorRecord,
		[switch] $ScriptErrorText
	)
    	if ($args) { 
		$args | write-host  -foregroundcolor "yellow"
		$args | out-file $env:computername-stdout.txt -append
	}
	$input | write-host  -foregroundcolor "yellow"
	$input | out-file $env:computername-stdout.txt -append
}

function update-diagreport {
	Param ( $id, $name, $verbosity)
	if ($args) { 
		$args | write-host  -foregroundcolor "yellow"
		$args | out-file $env:computername-stdout.txt -append
		}
	$input | write-host  -foregroundcolor "yellow"
	$input | out-file $env:computername-stdout.txt -append

}


# CompressCollectFiles function
# ---------------------
# Description:
#       This function compresses files in a ZIP or CAB file, collecting these files after the ZIP file is created
#       ZIP format is way faster than CAB but - once Shell is used for ZIP files, there is no support for ZIP files on ServerCore
#       Where support for ZIP files is inexistent (like on ServerCore), function will automatically switch to CAB
#
# Arguments:
#		filesToCollect: Folder or Files that to be collected (Ex: C:\windows\*.txt). This value can also be an array.
#       DestinationFileName: Destination name for the zip file (Ex: MyZipFile.ZIP or MyCabFile.CAB)
#		fileDescription: Individual description of the zip file 
#		sectionDescription: Section description.
#       Recursive: Copy files in subfolders
#       renameOutput: Add the %ComputerName% prefix to the ZIP file name - if not existent
#       noFileExtensionsOnDescription: Do not add file extension to the file description (Default format is $fileDescription ($FileExtension))
#       Verbosity: When $collectFiles is true, $Verbosity is the verbosity level for CollectFiles function
#       DoNotCollectFile: If present, function will generate the ZIP file but it will not collect it
#       ForegroundProcess: *Only for CAB files - By default CAB files are compressed in a Background process. Use -ForegroundProcess to force waiting for compression routine to complete before continuing.
#       $NumberOfDays: Do not add files older than $NumberOfDays days to the compressed files
#		$CheckFileInUse:  If present, function will check all files if they are in-used recursively, but it will take more time and may cause some performance issues

Function CompressCollectFiles
{
	PARAM($filesToCollect,
		[string]$DestinationFileName="File.zip",
		[switch]$Recursive,
		[string]$fileDescription="File", 
		[string]$sectionDescription="Section",
		[boolean]$renameOutput=$true,
		[switch]$noFileExtensionsOnDescription,
		[string]$Verbosity="Informational",
		[switch]$DoNotCollectFile,
		[switch]$ForegroundProcess=$false,
		[int]$NumberOfDays=0,
		[switch]$CheckFileInUse
	)

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[CompressCollectFiles]" -InvokeInfo $MyInvocation
		continue
	}

	$FileFormat = [System.IO.Path]::GetExtension($DestinationFileName)
	if ($FileFormat.Length -ne 4) {$FileFormat = ".zip"}
	if (((-not (Test-Path -Path (join-path ([Environment]::SystemDirectory) "shell32.dll"))) -or ((-not (Test-Path -Path (join-path ($Env:windir) "explorer.exe"))))) -and ($FileFormat -eq ".zip"))
	{
		"[CompressCollectFiles] - File format was switched to .CAB once shell components is not present" | WriteTo-StdOut -ShortFormat
		$FileFormat = ".cab"
	}
	
	if ($OSVersion.Major -lt 6) 
	{
		"[CompressCollectFiles] - File format was switched to .CAB once this OS does not support ZIP files" | WriteTo-StdOut -ShortFormat
		$FileFormat = ".cab"
	}

	if ($NumberOfDays -ne 0)
	{
		"[CompressCollectFiles] Restrict files older than $NumberOfDays days" | WriteTo-StdOut -ShortFormat
		$OldestFileDate = (Get-Date).AddDays(($NumberOfDays * -1))
	}

	if (($renameOutput -eq $true) -and (-not $DestinationFileName.StartsWith($ComputerName))) 
	{
		$CompressedFileNameWithoutExtension = $ComputerName + "_" + [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
	} else {
		$CompressedFileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
	}

	if (($FileFormat -eq ".cab") -and ($ForegroundProcess -eq $false) -and ($DoNotCollectFile.IsPresent))
	{
		"[CompressCollectFiles] Switching to Foreground execution as background processing requires file collection and -DoNotCollectFile iscurrently set" | WriteTo-StdOut -ShortFormat
		$ForegroundProcess = $true
	}
	
	$CompressedFileName = ($PWD.Path) + "\" + $CompressedFileNameWithoutExtension + $FileFormat

	if ($FileFormat -eq ".cab")
	{
		#Create DDF File
		$ddfFilename = Join-Path $PWD.Path ([System.IO.Path]::GetRandomFileName())
		
	    ".Set DiskDirectoryTemplate=" + "`"" + $PWD.Path + "`"" | Out-File -FilePath $ddfFilename -Encoding "UTF8";
	    ".Set CabinetNameTemplate=`"" + [IO.Path]::GetFileName($CompressedFileName) + "`""| Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	 
	    ".Set Cabinet=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set Compress=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set InfAttr=" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set FolderSizeThreshold=2000000" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxCabinetSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxDiskSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	}

	$ShellGetAllItems = {
	PARAM ($ShellFolderObj, $ZipFileName)
		if ($ShellFolderObj -is "System.__ComObject")
		{
			$ArrayResults = @()
			foreach ($ZipFileItem in $ShellFolderObj.Items())
			{
				$ArrayResults += $ZipFileItem.Path.Substring($ZipFileName.Length + 1)
				
				if ($ZipFileItem.IsFolder)
				{
					$ArrayResults += $ShellGetAllItems.Invoke((new-object -com Shell.Application).NameSpace($ZipFileItem.Path), $ZipFileName)
				}
			}
			return $ArrayResults
		}
	}

	ForEach ($pathFilesToCollect in $filesToCollect) 
	{
		"[CompressCollectFiles] Compressing " + $pathFilesToCollect + " to " + [System.IO.Path]::GetFileName($CompressedFileName) | WriteTo-StdOut -ShortFormat

		if (test-path ([System.IO.Path]::GetDirectoryName($pathFilesToCollect)) -ErrorAction SilentlyContinue) 
		{
			if ($Recursive.IsPresent) 
			{
				if (($pathFilesToCollect.Contains('*') -eq $false) -and ($pathFilesToCollect.Contains('?') -eq $false) -and [System.IO.Directory]::Exists($pathFilesToCollect))
				{
					#If the path looks like a folder and a folder with same name exists, consider that the file is a folder
					$FileExtension = '*.*'
					$RootFolder = $pathFilesToCollect
				}
				else
				{
					$FileExtension = Split-Path $pathFilesToCollect -leaf
					$RootFolder = [System.IO.Path]::GetDirectoryName($pathFilesToCollect)
				}
				if (($FileExtension -eq "*.*") -and ($FileFormat -eq ".zip") -and ($NumberOfDays -eq 0) -and ($CheckFileInUse.IsPresent -eq $false))
				{
					#Optimization to collect subfolders on ZIP files
					$FilestobeCollected = Get-ChildItem -Path $RootFolder
				} 
				else 
				{
					$FilestobeCollected = Get-ChildItem -Path $RootFolder -Include $FileExtension -Recurse
					$FilestobeCollected = $FilestobeCollected | Where-Object {$_.PSIsContainer -eq $false}
				}
			} 
			else 
			{
				#a folder without recurse, or a file without recurse, or an extension filter without recurse
				$FilestobeCollected = Get-ChildItem -Path $pathFilesToCollect | Where-Object {$_.PSIsContainer -eq $false}
			}
			
			if ((($FilestobeCollected -is [array]) -and ($FilestobeCollected.Count -gt 0)) -or ($FilestobeCollected -ne $null))
			{
				if ($NumberOfDays -ne 0)
				{
					$StringFilesExcluded = ''
					Foreach ($FileinCollection in ($FilestobeCollected | Where-Object {$_.LastWriteTime -lt $OldestFileDate}))
					{
						$StringFilesExcluded += (' ' * 10) + '- ' + ($FileinCollection.FullName) + " - Date: " + ($FileinCollection.LastWriteTime.ToShortDateString()) + "`r`n"
					}
					if ($StringFilesExcluded -ne '')
					{
						"Files not included in compressed results as they are older than " + $OldestFileDate.ToShortDateString() + ":`r`n" + $StringFilesExcluded | WriteTo-StdOut -ShortFormat
						$FilestobeCollected = $FilestobeCollected | Where-Object {$_.LastWriteTime -ge $OldestFileDate}
					}
				}
				$IsAnyFileInUse = $false
				if($CheckFileInUse.IsPresent)
				{
					$NotInUseFiles=@()
					foreach($file in $FilestobeCollected)
					{
						if((Is-FileInUse -FilePath ($file.FullName)) -eq $false)
						{
							$NotInUseFiles += $file
						}
						else
						{
							$IsAnyFileInUse = $true
							"[CompressCollectFiles] File " + $file.FullName + " is currently in use - Skipping" | WriteTo-StdOut -ShortFormat
						}
					}
					$FilestobeCollected = $NotInUseFiles
				}
				if (($FileExtension -ne "*.*") -or ($FileFormat -ne ".zip") -or ($NumberOfDays -ne 0) -or  $IsAnyFileInUse)
				{
					$SubfolderToBeCollected = $FilestobeCollected | Select-Object -Unique "Directory" | %{$_."Directory"} #Modified to work on PS 1.0.
				}
				elseif(($CheckFileInUse.IsPresent) -and ($IsAnyFileInUse -eq $false))
				{
					#Means the CheckFileInUse parameter is present but there is no file in used, So get the FilestobeCollected without recurse again
					$FilestobeCollected = Get-ChildItem -Path $RootFolder
				}
			}
			if ((($FilestobeCollected -is [array]) -and ($FilestobeCollected.Count -gt 0)) -or ($FilestobeCollected -ne $null))
			{
				
		 		switch ($FileFormat)
				{
					".zip" 
					{
						#Create file if it does not exist, otherwise just add to the ZIP file name
						$FilesToSkip = @()
						if (-not (Test-Path ($CompressedFileName))) 
						{
							Set-Content $CompressedFileName ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
						}
						else 
						{
							#Need to check file name conflicts, otherwise Shell will raise a message asking for overwrite
							if ($RootFolder -eq $null) {$RootFolder = [System.IO.Path]::GetDirectoryName($pathFilesToCollect)}
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							$FilesToBeCollectedFullPath = ($FilestobeCollected | %{$_."FullName"})
							$AllZipItems = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
							foreach ($ZipFileItem in $AllZipItems)
							{
								$FileNameToCheck = $RootFolder + "\" + $ZipFileItem
								if ($FilesToBeCollectedFullPath -contains $FileNameToCheck)
								{
									if (($FileExtension -eq "*.*") -or ([System.IO.Directory]::Exists($FileNameToCheck) -eq $false)) #Check if it is a folder, so it will not fire a message on stdout.log
									{
										#Error - File Name Conflics exist
										$ErrorDisplay = "[CompressCollectFiles] Error: One or more file name conflicts when compressing files were detected:`r`n"
										$ErrorDisplay += "        File Name   : "+ $FileNameToCheck + "`r`n"
										$ErrorDisplay += "        Zip File    : " + $CompressedFileName + "`r`n"
										$ErrorDisplay += "   File/ Folder will not be compressed."
										$ErrorDisplay | WriteTo-StdOut
									}
									$FilesToSkip += $FileNameToCheck
								}
							}
						}
						
						$ExecutionTimeout = 10 #Time-out for compression - in minutes

						$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						$InitialZipItemCount = 0
						
						if (($Recursive.IsPresent) -and (($FileExtension -ne "*.*") -or ($NumberOfDays -ne 0) -or $IsAnyFileInUse))
						{
							#Create Subfolder structure on ZIP files
							#$TempFolder = mkdir -Path (Join-Path $Env:TEMP ("\ZIP" + (Get-Random).toString()))
							$TempFolder = mkdir -Path (Join-Path $PWD.Path ("\ZIP" + [System.IO.Path]::GetRandomFileName()))
							$TempFolderObj = (new-object -com Shell.Application).NameSpace($TempFolder.FullName)
							
							foreach ($SubfolderToCreateOnZip in ($SubfolderToBeCollected | %{$_."FullName"})) #modified to support PS1.0 -ExpandProperty doesn't behave the same in PS 1.0
							{
								$RelativeFolder = $SubfolderToCreateOnZip.Substring($RootFolder.Length)
								if ($RelativeFolder.Length -gt 0)
								{
									$TempFolderToCreate = (Join-Path $TempFolder $RelativeFolder)
									MKDir -Path $TempFolderToCreate -Force | Out-Null
									"Temporary file" |Out-File -FilePath ($TempFolderToCreate + "\_DeleteMe.Txt") -Append #Temporary file just to make sure file isn't empty so it won't error out when using 'CopyHere
								}
							}
							
							#Create subfolder structure on ZIP file:
							
							foreach ($ParentTempSubfolder in $TempFolder.GetDirectories("*.*", [System.IO.SearchOption]::AllDirectories))
							{
								if (($AllZipItems -eq $null) -or ($AllZipItems -notcontains ($ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length+1))))
								{
									
									$TimeCompressionStarted = Get-Date
									$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName + $ParentTempSubfolder.Parent.FullName.Substring($TempFolder.FullName.Length))
									$InitialZipItemCount = $ZipFileObj.Items().Count
									$ZipFileObj.CopyHere($ParentTempSubfolder.FullName, $DontShowDialog)

									do
									{
										sleep -Milliseconds 100
										
										if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge 2)
										{
											$ErrorDisplay = "[CompressCollectFiles] Compression routine will be terminated due it reached a timeout of 2 minutes to create a subfolder on zip file:`r`n"
											$ErrorDisplay += "        SubFolder   : " + $RootFolder + $ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length) + "`r`n"
											$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
											$ErrorDisplay | WriteTo-StdOut
											$TimeoutOcurred = $true
										}
																
									} while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
									
									#$AllZipItems += [System.IO.Directory]::GetDirectories($ParentTempSubfolder.FullName, "*.*", [System.IO.SearchOption]::AllDirectories) | ForEach-Object -Process {$_.Substring($TempFolder.FullName.Length + 1)}
									$AllZipItems  = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
								}
							}
						}
						
						if (($ZipFileObj -eq $null) -or ($ZipFileObj.Self.Path -ne $CompressedFileName))
						{
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						}
					}
				}
		
				$FilestobeCollected | ForEach-object -process {
				
					$FileName = Split-Path $_.Name -leaf
					$FileNameFullPath = $_.FullName
					if ([System.IO.Directory]::Exists($pathFilesToCollect))
					{
						$ParentFolderName = [System.IO.Path]::GetFullPath($pathFilesToCollect)
					}
					else
					{
						$ParentFolderName = [System.IO.Path]::GetDirectoryName($pathFilesToCollect).Length
					}
					
					if (($Recursive.IsPresent) -and ([System.IO.Path]::GetDirectoryName($FileNameFullPath).Length -gt $ParentFolderName.Length))
					{
						$RelativeFolder = [System.IO.Path]::GetDirectoryName($FileNameFullPath).Substring($RootFolder.Length)
					} else {
						$RelativeFolder = ""
						$CurrentZipFolder = ""
					}
					
			 		switch ($FileFormat)
					{
						".zip" 
						{
							$TimeCompressionStarted = Get-Date
							$TimeoutOcurred = $false

							if (($FileExtension -eq "*.*") -and ([System.IO.Directory]::Exists($FileNameFullPath)))
							{
								#Check if folder does not have any file
								if (([System.IO.Directory]::GetFiles($FileNameFullPath, "*.*", [System.IO.SearchOption]::AllDirectories)).Count -eq 0)
								{
									$FilesToSkip += $FileNameFullPath
									"[CompressCollectFiles] Folder $FileNameFullPath will not be compressed since it does not contain any file`r`n"
								}
							}

							if ($RelativeFolder -ne $CurrentZipFolder)
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace((join-path $CompressedFileName $RelativeFolder))
								ForEach ($TempFile in $ZipFileObj.Items()) 
								{
									#Remove temporary file from ZIP
									if ($TempFile.Name.StartsWith("_DeleteMe")) 
									{
										$DeleteMeFileOnTemp = (Join-Path $TempFolder.FullName "_DeleteMe.TXT")
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path $DeleteMeFileOnTemp}
										$TempFolderObj.MoveHere($TempFile)
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path (Join-Path $TempFolder.FullName "_DeleteMe.TXT")}
									}
								}
								$CurrentZipFolder = $RelativeFolder
							} 
							elseif (($RelativeFolder.Length -eq 0) -and ($ZipFileObj.Self.Path -ne $CompressedFileName))
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							}
							
							if (($FilesToSkip -eq $null) -or ($FilesToSkip -notcontains $FileNameFullPath))
							{
								"             + " + $FileNameFullPath + " to " + ([System.IO.Path]::GetFileName($CompressedFileName)) + $ZipFileObj.Self.Path.Substring($CompressedFileName.Length) | WriteTo-StdOut -ShortFormat
								$InitialZipItemCount = $ZipFileObj.Items().Count
								$ZipFileObj.CopyHere($FileNameFullPath, $DontShowDialog)
						
								while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
								{
									sleep -Milliseconds 200
									
									if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge $ExecutionTimeout)
									{
										$ErrorDisplay = "[CompressCollectFiles] Compression routine will be terminated due it reached a timeout of $ExecutionTimeout minutes:`r`n"
										$ErrorDisplay += "        File Name   : $FileNameFullPath `r`n"
										$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
										$ErrorDisplay | WriteTo-StdOut
										$TimeoutOcurred = $true
									}
															
								} 
							}
						}
						".cab"
						{
							if ($RelativeFolder -ne $CurrentCabFolder)
							{
								$ListOfFilesonDDF += ".Set DestinationDir=`"" + $RelativeFolder + "`"`r`n"
								$CurrentCabFolder = $RelativeFolder
							}
							$ListOfFilesonDDF += "`"" + $FileNameFullPath + "`"`r`n" 
							$StringFilesIncluded += (' ' * 10) + '+ ' + $FileNameFullPath + "`r`n" 
						}
					}
				}	
				#Add condition to check if the $TempFolder actually exists.
				if(($TempFolder -ne $null) -and (Test-Path -Path $TempFolder.FullName)) { Remove-Item -Path $TempFolder.FullName -Recurse }
			} else {
				"[CompressCollectFiles] No files found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
			}
		} else {
			"[CompressCollectFiles] Path not found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
		}		
	} #ForEach
	
	if (($FileFormat -eq ".zip") -and (Test-Path $CompressedFileName) -and (-not $DoNotCollectFile.IsPresent))
	{
		if ($noFileExtensionsOnDescription.IsPresent)
		{
			CollectFiles -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -renameOutput ($renameOutput -eq $true) -Verbosity $Verbosity -noFileExtensionsOnDescription -InvokeInfo $MyInvocation
		}
		else
		{
			CollectFiles -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -renameOutput ($renameOutput -eq $true) -Verbosity $Verbosity -InvokeInfo $MyInvocation
		}
	}
	
	if ($FileFormat -eq ".cab")
	{					
		if ($ListOfFilesonDDF -ne $null) 
		{
			$ListOfFilesonDDF | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		    "Files to be included in " + [System.IO.Path]::GetFileName($CompressedFileName) + ":`r`n" + $StringFilesIncluded | WriteTo-StdOut -ShortFormat

			$AddToCommandLine = " > nul"
			
			if ($debug -eq $true)
			{
				"MakeCab DDF Contents: " | WriteTo-StdOut -ShortFormat
				Get-Content $ddfFilename | Out-String | WriteTo-StdOut
				$AddToCommandLine = " > 1.txt & type 1.txt"
			}
			
			if ($ForegroundProcess.IsPresent)
			{
				$commandToRun = ($env:windir + "\system32\cmd.exe /c `"`"" + $env:windir + "\system32\makecab.exe`" /f `"" + $ddfFilename + "`"$AddToCommandLine`"")
				if ($noFileExtensionsOnDescription.IsPresent -eq $true)
				{
					if ($DoNotCollectFile.IsPresent)
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription -collectFiles $false
					}
					else
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
					}
				}
				else
				{
					if ($DoNotCollectFile.IsPresent)
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -collectFiles $false
					}
					else
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity
					}
				}
				
				if ($debug -ne $true)
				{
					Remove-Item $ddfFilename
				}
			} 
			else 
			{
				if ($debug -ne $true)
				{
					$AddToCommandLine += " & del `"$ddfFilename`""
				}
				
				$commandToRun = ($env:windir + "\system32\cmd.exe")
				$commandArguments = ("/c `"`"" + $env:windir + "\system32\makecab.exe`" /f `"" + $ddfFilename + "`"$AddToCommandLine`"")
				
				if ($noFileExtensionsOnDescription.IsPresent -eq $true)
				{
					BackgroundProcessCreate -ProcessName $commandToRun -Arguments $commandArguments -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				} 
				else 
				{
					BackgroundProcessCreate -ProcessName $commandToRun  -Arguments $commandArguments -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				}
			}
		} 
		else 
		{
			"Unable to find files to be collected" | WriteTo-StdOut
			Remove-Item $ddfFilename
		}
	} 
}




##################################################################################################

function stopanddeletealltraces {
	$foo =logman | Select-Object
	foreach ($f in $foo) { if($f -match "(wapdebug-\d+).*")  { logman stop $matches[1]}}
	foreach ($f in $foo) { if($f -match "(wapdebug-\d+).*")  { logman delete $matches[1]}}

}



######################################################################
#
# Navigation
#
##################################
function home {
	C:
	cd $env:homepath
}
function docs{
	C:
	cd $env:homepath\documents
}
function t {
	C:
	cd c:\temp
}
function sdp {
	d:
	cd d:\sdp\dev\systemcenter
}

Function WaitForBackgroundProcesses($MaxBackgroundProcess = 0, $SessionName = 'AllSessions', $OverrideMaxWaitTime = $null)
{

	$ProcessCloseRequested=New-Object System.Collections.ArrayList
	$BackgroundProcessToWait = [array](Get-DiagBackgroundProcess -SessionName $SessionName)
	
	$ProcessIdNotified = @()
	while (($BackgroundProcessToWait | Measure-Object).Count -gt ($MaxBackgroundProcess))
	{
		if (-not $WaitMSG)
		{
			$ProcessDisplay = ""
			foreach ($Process in $BackgroundProcessToWait)
			{
				[string] $ProcessID = $Process.Id
				$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
				$ProcessDisplay += "`r`n    Session Name: $SessionId `r`n"
				$ProcessDisplay += "    Process ID  : $ProcessID `r`n"
				$ProcessDisplay += "    Command Line: " + $Process.StartInfo.FileName + " " + $Process.StartInfo.Arguments + "`r`n"
				$ProcessDisplay += "    Running for : " + (GetAgeDescription -TimeSpan (new-TimeSpan $Process.StartTime)) + "`r`n"
				
			}
									
			"[WaitForBackgroundProcesses] Waiting for one background process(es) to finish in session [$SessionName]. Current background processes:`r`n" + $ProcessDisplay | WriteTo-StdOut
			$WaitMSG = $true
		}
		
		$BackgroundProcessToWait = [array](Get-DiagBackgroundProcess -SessionName $SessionName)
		
		if (($BackgroundProcessToWait | Measure-Object).Count -ne 0)
		{
			sleep -Milliseconds 500
		}
	
		#Check for timeout
		foreach ($Process in $BackgroundProcessToWait)
		{
			if($null -eq $Process){continue}
			$ExecutionTimeout = ($DiagProcessesBGProcessTimeout.get_Item($Process.Id))
			if ($OverrideMaxWaitTime -ne $null)
			{
				if ($ProcessIdNotified -notcontains $Process.Id)
				{
					"[WaitForBackgroundProcesses] Overriding process $($Process.Id) [Session $SessionName] time out from $ExecutionTimeout to $OverrideMaxWaitTime minutes." | WriteTo-StdOut 
					$ProcessIdNotified += $Process.Id
				}
				$ExecutionTimeout = ($OverrideMaxWaitTime)
			}
			if ($ExecutionTimeout -ne 0)
			{
				if ((New-TimeSpan -Start $Process.StartTime).Minutes -ge $ExecutionTimeout)
				{
					if (-not $ProcessCloseRequested.Contains($Process.Id))
					{
						[string] $ProcessID = $Process.Id
						$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
						$ProcessDisplay = "[WaitForBackgroundProcesses] A process will be terminated due it reached a timeout of $ExecutionTimeout minutes:`r`n"
						$ProcessDisplay += "        Session Name: [$SessionId] `r`n"
						$ProcessDisplay += "        Process ID  : $ProcessID `r`n"
						$ProcessDisplay += "        Start Time  : " + $Process.StartTime + "`r`n"
						$ProcessDisplay += "        Command Line: " + $Process.StartInfo.FileName + " " + $Process.StartInfo.Arguments + "`r`n"
						$ProcessDisplay += "        Running for : " + (GetAgeDescription -TimeSpan (new-TimeSpan $Process.StartTime)) + "`r`n"
						$ProcessDisplay | WriteTo-StdOut
					}
					
					if ($Process.HasExited -eq $false)
					{
						$Process.CloseMainWindow()
						$ProcessCloseRequested.Add($Process.Id)
					}
					
					if ((New-TimeSpan -Start $Process.StartTime).Minutes -gt ($ExecutionTimeout))
					{
						if ($Process.HasExited -eq $false)
						{
							"Killing process " + $Process.Id + " once it did not close orderly after " + ($ExecutionTimeout +1) + " minutes" | WriteTo-StdOut
							$Process.Kill()
						}
					}
				}
			}
		}
	}
	
	if ($WaitMSG) 
	{
		$ProcessDisplay = ""
		foreach ($Process in ($DiagProcesses | Where-Object {$_.HasExited -eq $true}))
		{
			[string] $ProcessID = $Process.Id
			$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
			$ProcessDisplay += "`r`n    Session Name: [$SessionId] `r`n"
			$ProcessDisplay += "    Process ID  : $ProcessID `r`n"
			$ProcessDisplay += "    Run time    : " + (GetAgeDescription -TimeSpan (new-TimeSpan -Start $Process.StartTime -End $Process.ExitTime))
		}
		"[WaitForBackgroundProcesses] The following background process(es) finished executing: `r`n" + $ProcessDisplay | WriteTo-StdOut
	}

	#If there are process there were terminated, files needs to be collected
	$NumberofTerminatedProcesses = [array] ($DiagProcesses | Where-Object {$_.HasExited -eq $true})
	
	if (($NumberofTerminatedProcesses | Measure-Object).Count -gt 0)
	{
		CollectBackgroundProcessesFiles
	}

}




#Return an array with process running in a given session
Function Get-DiagBackgroundProcess($SessionName = 'AllSessions')
{
	if ($DiagProcesses.Count -gt 0)
	{
		$RunningDiagProcesses = [array] ($DiagProcesses | Where-Object {$_.HasExited -eq $false})
		if ($RunningDiagProcesses.Count -ne $null)
		{
			if ($SessionName -eq 'AllSessions')
			{
				return ($RunningDiagProcesses)
			}
			else
			{
				$RunningDiagProcessesInSession = @()
				$RunningDiagProcesses | ForEach-Object -Process {
					if (($DiagProcessesSessionNames.get_Item($_.Id) -ne $null) -and ($DiagProcessesSessionNames.get_Item($_.Id) -eq $SessionName))
					{
						$RunningDiagProcessesInSession += $_
					}
				}
				return $RunningDiagProcessesInSession
			}
		}
		else 
		{
			return $null	
		}
	} 
	else 
	{
		return $null
	}
}





Function WaitForBackgroundProcesses($MaxBackgroundProcess = 0, $SessionName = 'AllSessions', $OverrideMaxWaitTime = $null)
{

	$ProcessCloseRequested=New-Object System.Collections.ArrayList
	$BackgroundProcessToWait = [array](Get-DiagBackgroundProcess -SessionName $SessionName)
	
	$ProcessIdNotified = @()
	while (($BackgroundProcessToWait | Measure-Object).Count -gt ($MaxBackgroundProcess))
	{
		if (-not $WaitMSG)
		{
			$ProcessDisplay = ""
			foreach ($Process in $BackgroundProcessToWait)
			{
				[string] $ProcessID = $Process.Id
				$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
				$ProcessDisplay += "`r`n    Session Name: $SessionId `r`n"
				$ProcessDisplay += "    Process ID  : $ProcessID `r`n"
				$ProcessDisplay += "    Command Line: " + $Process.StartInfo.FileName + " " + $Process.StartInfo.Arguments + "`r`n"
				$ProcessDisplay += "    Running for : " + (GetAgeDescription -TimeSpan (new-TimeSpan $Process.StartTime)) + "`r`n"
				
			}
									
			"[WaitForBackgroundProcesses] Waiting for one background process(es) to finish in session [$SessionName]. Current background processes:`r`n" + $ProcessDisplay | WriteTo-StdOut
			$WaitMSG = $true
		}
		
		$BackgroundProcessToWait = [array](Get-DiagBackgroundProcess -SessionName $SessionName)
		
		if (($BackgroundProcessToWait | Measure-Object).Count -ne 0)
		{
			sleep -Milliseconds 500
		}
	
		#Check for timeout
		foreach ($Process in $BackgroundProcessToWait)
		{
			if($null -eq $Process){continue}
			$ExecutionTimeout = ($DiagProcessesBGProcessTimeout.get_Item($Process.Id))
			if ($OverrideMaxWaitTime -ne $null)
			{
				if ($ProcessIdNotified -notcontains $Process.Id)
				{
					"[WaitForBackgroundProcesses] Overriding process $($Process.Id) [Session $SessionName] time out from $ExecutionTimeout to $OverrideMaxWaitTime minutes." | WriteTo-StdOut 
					$ProcessIdNotified += $Process.Id
				}
				$ExecutionTimeout = ($OverrideMaxWaitTime)
			}
			if ($ExecutionTimeout -ne 0)
			{
				if ((New-TimeSpan -Start $Process.StartTime).Minutes -ge $ExecutionTimeout)
				{
					if (-not $ProcessCloseRequested.Contains($Process.Id))
					{
						[string] $ProcessID = $Process.Id
						$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
						$ProcessDisplay = "[WaitForBackgroundProcesses] A process will be terminated due it reached a timeout of $ExecutionTimeout minutes:`r`n"
						$ProcessDisplay += "        Session Name: [$SessionId] `r`n"
						$ProcessDisplay += "        Process ID  : $ProcessID `r`n"
						$ProcessDisplay += "        Start Time  : " + $Process.StartTime + "`r`n"
						$ProcessDisplay += "        Command Line: " + $Process.StartInfo.FileName + " " + $Process.StartInfo.Arguments + "`r`n"
						$ProcessDisplay += "        Running for : " + (GetAgeDescription -TimeSpan (new-TimeSpan $Process.StartTime)) + "`r`n"
						$ProcessDisplay | WriteTo-StdOut
					}
					
					if ($Process.HasExited -eq $false)
					{
						$Process.CloseMainWindow()
						$ProcessCloseRequested.Add($Process.Id)
					}
					
					if ((New-TimeSpan -Start $Process.StartTime).Minutes -gt ($ExecutionTimeout))
					{
						if ($Process.HasExited -eq $false)
						{
							"Killing process " + $Process.Id + " once it did not close orderly after " + ($ExecutionTimeout +1) + " minutes" | WriteTo-StdOut
							$Process.Kill()
						}
					}
				}
			}
		}
	}
	
	if ($WaitMSG) 
	{
		$ProcessDisplay = ""
		foreach ($Process in ($DiagProcesses | Where-Object {$_.HasExited -eq $true}))
		{
			[string] $ProcessID = $Process.Id
			$SessionId = $DiagProcessesSessionNames.get_Item($Process.Id)
			$ProcessDisplay += "`r`n    Session Name: [$SessionId] `r`n"
			$ProcessDisplay += "    Process ID  : $ProcessID `r`n"
			$ProcessDisplay += "    Run time    : " + (GetAgeDescription -TimeSpan (new-TimeSpan -Start $Process.StartTime -End $Process.ExitTime))
		}
		"[WaitForBackgroundProcesses] The following background process(es) finished executing: `r`n" + $ProcessDisplay | WriteTo-StdOut
	}

	#If there are process there were terminated, files needs to be collected
	$NumberofTerminatedProcesses = [array] ($DiagProcesses | Where-Object {$_.HasExited -eq $true})
	
	if (($NumberofTerminatedProcesses | Measure-Object).Count -gt 0)
	{
		CollectBackgroundProcessesFiles
	}

}




#Return an array with process running in a given session
Function Get-DiagBackgroundProcess($SessionName = 'AllSessions')
{
	if ($DiagProcesses.Count -gt 0)
	{
		$RunningDiagProcesses = [array] ($DiagProcesses | Where-Object {$_.HasExited -eq $false})
		if ($RunningDiagProcesses.Count -ne $null)
		{
			if ($SessionName -eq 'AllSessions')
			{
				return ($RunningDiagProcesses)
			}
			else
			{
				$RunningDiagProcessesInSession = @()
				$RunningDiagProcesses | ForEach-Object -Process {
					if (($DiagProcessesSessionNames.get_Item($_.Id) -ne $null) -and ($DiagProcessesSessionNames.get_Item($_.Id) -eq $SessionName))
					{
						$RunningDiagProcessesInSession += $_
					}
				}
				return $RunningDiagProcessesInSession
			}
		}
		else 
		{
			return $null	
		}
	} 
	else 
	{
		return $null
	}
}




Function BackgroundProcessCreate([string]$ProcessName, 
								[string]$Arguments,
								$filesToCollect, 
								[string]$fileDescription="", 
								[string]$sectionDescription="", 
								[string]$Verbosity="Informational",
								[switch]$noFileExtensionsOnDescription,
								[boolean]$renameOutput = $true,
								[boolean]$CollectFiles = $true,
								[int] $TimeoutMinutes = 15,
								[scriptblock]$PostProcessingScriptBlock,
								[switch] $SkipMaxParallelDiagCheck,
								[string] $SessionName = 'Default')
{
	if ($MaxParallelDiagProcesses -eq $null)
	{
		#$MaxParallelDiagProcesses = Get-MaxBackgroundProcesses
		Set-Variable -Name MaxParallelDiagProcesses -Value (Get-MaxBackgroundProcesses)
	}
	
	#Wait until there are slots available
	"[BackgroundProcessCreate] Creating background process: [(Session: " + $SessionName+ ") Process: `'" + $ProcessName + "`' - Arguments: `'" + $Arguments + "`']" | WriteTo-StdOut
	$WaitMSG = $false

	if ($SkipMaxParallelDiagCheck.IsPresent -eq $false)
	{
		WaitForBackgroundProcesses -MaxBackgroundProcess $MaxParallelDiagProcesses
	}
	else
	{
		#When SkipMaxParallelDiagCheck is used, increase the number of allowed background processes by 1 while the new process is running
		if ($Global:OverrideMaxBackgroundProcesses -eq $null)
		{
			$Global:OverrideMaxBackgroundProcesses = $MaxParallelDiagProcesses
		}
		$Global:OverrideMaxBackgroundProcesses++
		Set-MaxBackgroundProcesses -NumberOfProcesses $Global:OverrideMaxBackgroundProcesses
	}
	
	#Start process in background
	$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments 

	#Fill out Diagnostic variables so we can use in the future
	[Void] $DiagProcesses.Add($Process)
	$DiagProcessesFileDescription.Add($Process.Id, $fileDescription)
	$DiagProcessesSectionDescription.Add($Process.Id, $sectionDescription)
	$DiagProcessesVerbosity.Add($Process.Id, $Verbosity)
	$DiagProcessesFilesToCollect.Add($Process.Id, $filesToCollect)
	$DiagProcessesAddFileExtension.Add($Process.Id, -not ($noFileExtensionsOnDescription.IsPresent))
	$DiagProcessesBGProcessTimeout.Add($Process.Id, $TimeoutMinutes)
	$DiagProcessesSessionNames.Add($Process.Id, $SessionName)
	if ($SkipMaxParallelDiagCheck.IsPresent)
	{
		$DiagProcessesSkipMaxParallelDiagCheck.Add($Process.Id, $true)
	}

	if($null -ne $PostProcessingScriptBlock)
	{
		if($Process.HasExited)
		{
			"[BackgroundProcessCreate] Process already exited. Running `$PostProcessingScriptBlock" | WriteTo-StdOut -shortformat
			& $PostProcessingScriptBlock
		}
		else
		{
			if((test-path variable:psversiontable) -and ($PSVersionTable.PSVersion.Major -ge 2))
			{
				$Process.EnableRaisingEvents = $true
				$postProcSB = @"
				. .\utils_cts.ps1
				"[Utils_CTS] Running PostProcessingScriptBlock" | WriteTo-StdOut -ShortFormat
				$($PostProcessingScriptBlock.ToString())
"@
				"[BackgroundProcessCreate] Registering an event for process exit and attaching script block. ScriptBlock = `r`n $postProcSB" | WriteTo-StdOut -ShortFormat
				
				$ModifiedSB = [Scriptblock]::Create($postProcSB);
				Register-ObjectEvent -InputObject $Process -EventName "Exited" -Action $ModifiedSB -SourceIdentifier $Process.Id			
			}
			else
			{
				$DiagProcessesScriptblocks.Add($Process.Id, $PostProcessingScriptBlock)
			}
		}
	}
	$DiagProcessesRenameOutput.Add($Process.Id, $renameOutput)
	
	Return $Process
	
}
Function Set-MaxBackgroundProcesses
{
	param([int]$NumberOfProcesses=2,[switch]$Default)
	if($Default)
	{
		"Set-MaxBackgroundProcesses called with -Default" | WriteTo-StdOut -ShortFormat
		Remove-Variable "OverrideMaxBackgroundProcesses" -Scope Global -ErrorAction SilentlyContinue
	}
	else
	{
		"Set-MaxBackgroundProcesses called with NumberOfProcesses = $NumberOfProcesses" | WriteTo-StdOut -ShortFormat
		Set-Variable "OverrideMaxBackgroundProcesses" -Scope Global -Value $NumberOfProcesses
	}
}


Function Get-MaxBackgroundProcesses
{
	$overrideVal = 0
	if(($global:OverrideMaxBackgroundProcesses -ne $null) -and ($global:OverrideMaxBackgroundProcesses -is [int]))
	{
		$overrideVal = [Math]::Abs(($global:OverrideMaxBackgroundProcesses -as [int]))
	}
	$Win32CS = Get-WmiObject -Class Win32_ComputerSystem
	#Pre-WinVista do not support NumberOfLogicalProcessors:
	$NumberOfCores = $Win32CS.NumberOfLogicalProcessors
	
	if ($NumberOfCores -eq $null)
	{
		$NumberOfCores = $Win32CS.NumberOfProcessors
	}
	
	return [Math]::Max($NumberOfCores,$overrideVal)
}



Function Run-ExternalPSScript([string]$ScriptPath,  
				$filesToCollect = "", 
				[string]$fileDescription="", 
				[string]$sectionDescription="", 
				[boolean]$collectFiles=$false,
				[string]$Verbosity="Informational",
				[switch]$BackgroundExecution,
				[string]$BackgroundExecutionSessionName = 'Default',
				[int] $BackgroundExecutionTimeOut = 15,
				[switch] $BackgroundExecutionSkipMaxParallelDiagCheck,
				[scriptblock] $BackgroundExecutionPostProcessingScriptBlock)
{

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[RunExternalPSScript (ScriptPath = $ScriptPath) (filesToCollect: $filesToCollect) (fileDescription: $fileDescription) (sectionDescription: $sectionDescription) (collectFiles $collectFiles)]" -InvokeInfo $MyInvocation
		$Error.Clear()
		continue
	}

	if ($BackgroundExecution.IsPresent)
	{
		$StringToAdd += " (Background Execution)"
	}
	
	$StringToAdd += " (Collect Files: $collectFiles)"
	
	if ($collectFiles -and ([string]::IsNullOrEmpty($fileDescription) -or [string]::IsNullOrEmpty($sectionDescription) -or [string]::IsNullOrEmpty($filesToCollect)))
	{
		"[RunExternalPSScript] ERROR: -CollectFiles argument is set to $true but a fileDescription, sectionDescription and/or filesToCollect were not specified`r`n   fileDescription: [$fileDescription]`r`n   sectionDescription: [$sectionDescription]`r`n   filesToCollect: [$filesToCollect]" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation
	}
	
	"[RunExternalPSScript] Running External PowerShell Script: $ScriptPath $ScriptArgumentCmdLine " + $StringToAdd | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat

	$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
	if (Test-Path $ScriptPath)
	{
		if ((test-path variable:\psversiontable) -and ($OSVersion.Major -gt 5))
		{
			# PowerShell 2.0+/ WinVista+
			$DisablePSExecutionPolicy = "`$context = `$ExecutionContext.GetType().GetField(`'_context`',`'nonpublic,instance`').GetValue(`$ExecutionContext); `$authMgr = `$context.GetType().GetField(`'_authorizationManager`',`'nonpublic,instance`'); `$authMgr.SetValue(`$context, (New-Object System.Management.Automation.AuthorizationManager `'Microsoft.PowerShell`'))"
			$PSArgumentCmdLine = "-command `"& { $DisablePSExecutionPolicy ;" + $ScriptPath + " $ScriptArgumentCmdLine}`""
		}
		else
		{
			# PowerShell 1.0 ($psversiontable variable does not exist in PS 1.0)
			$PSArgumentCmdLine = "-command `"& { invoke-expression (get-content `'" + $ScriptPath + "`'| out-string) }`""
		}
		
		if ($BackgroundExecution.IsPresent -eq $false)
		{	
			$process = ProcessCreate -Process "powershell.exe" -Arguments $PSArgumentCmdLine
			
			"PowerShell started with Process ID $($process.Id)" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
			"--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
			$process.WaitForExit()
			$StdoutOutput = $process.StandardOutput.ReadToEnd() 
			if ($StdoutOutput -ne $null)
			{
				($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			else
			{
				'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			$ProcessExitCode = $process.ExitCode
			
			if (($ProcessExitCode -ne 0) -or ($process.StandardError.EndOfStream -eq $false))
			{
				"[RunExternalPSScript] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode)  + " when running $ScriptPath"| WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
				$ProcessStdError = $process.StandardError.ReadToEnd()
				if ($ProcessStdError -ne $null)
				{
					"--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
				}
			}
			"--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat	
			
			if ($collectFiles -eq $true) 
			{	
				"[RunExternalPSScript] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
			}
			return $ProcessExitCode
		} 
		else 
		{ 
			$Process = BackgroundProcessCreate -ProcessName "powershell.exe" -Arguments $PSArgumentCmdLine -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -TimeoutMinutes $BackgroundExecutionTimeOut -PostProcessingScriptBlock $BackgroundExecutionPostProcessingScriptBlock -SkipMaxParallelDiagCheck:$BackgroundExecutionSkipMaxParallelDiagCheck -SessionName $BackgroundExecutionSessionName
			return $Process
		}
	}
	else
	{
		"[RunExternalPSScript] ERROR: Script [$ScriptPath] could not be found" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation
	}
}




Function ProcessCreate($Process, $Arguments = "", $WorkingDirectory = $null)
{
	
	"ProcessCreate($Process, $Arguments) called." | WriteTo-StdOut -ShortFormat
	
	$Error.Clear()
	$processStartInfo  = new-object System.Diagnostics.ProcessStartInfo
	$processStartInfo.fileName = $Process
	if ($Arguments.Length -ne 0) { $processStartInfo.Arguments = $Arguments }
	if ($WorkingDirectory -eq $null) {$processStartInfo.WorkingDirectory = (Get-Location).Path}
	$processStartInfo.UseShellExecute = $false
	$processStartInfo.RedirectStandardOutput = $true
	$processStartInfo.REdirectStandardError = $true
	
	#$process = New-Object System.Diagnostics.Process
	#$process.startInfo=$processStartInfo
	
	$process = [System.Diagnostics.Process]::Start($processStartInfo)
	
	if ($Error.Count -gt 0)
	{
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$PositionMessage = $Error[0].InvocationInfo.PositionMessage
		"[ProcessCreate] Error " + $errorCode + " on: " + $line + ": $errorMessage" | WriteTo-StdOut -IsError -InvokeInfo $MyInvocation

		$Error.Clear()
	}

	Return $process
}


function runcmd {
		Param(		[string]$commandToRun, 
				$filesToCollect = $null, 
				[string]$fileDescription="", 
				[string]$sectionDescription="", 
				[boolean]$collectFiles=$true,
				[switch]$useSystemDiagnosticsObject,
				[string]$Verbosity="Informational",
				[switch]$NoFileExtensionsOnDescription,
				[switch]$BackgroundExecution,
				[boolean]$RenameOutput=$false,
				[switch]$DirectCommand,
				[Scriptblock] $PostProcessingScriptBlock)


"[RunCMD] Running Command" + $StringToAdd + ":`r`n `r`n                      $commandToRun`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat

	# A note: if CollectFiles is set to False, background processing is not allowed
	# This is to avoid problems where multiple background commands write to the same file
	if (($BackgroundExecution.IsPresent -eq $false) -or ($collectFiles -eq $false))
	{	
		"--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
		
		if ($useSystemDiagnosticsObject.IsPresent) 
		{
			if ($DirectCommand.IsPresent)
			{
				if ($commandToRun.StartsWith("`""))
				{
					$ProcessName = $commandToRun.Split("`"")[1]
					$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
				} 
				elseif ($commandToRun.Contains(".exe"))
				# 2. No quote found - try to find a .exe on $commandToRun
				{
					$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
					$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
				}
				else
				{
					$ProcessName = "cmd.exe" 
					$Arguments = "/c `"" + $commandToRun + "`""
				}
				$process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			}
			else
			{
				$process = ProcessCreate -Process "cmd.exe" -Arguments ("/s /c `"" + $commandToRun + "`"")
			}
			$process.WaitForExit()
			$StdoutOutput = $process.StandardOutput.ReadToEnd() 
			if ($StdoutOutput -ne $null)
			{
				($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			else
			{
				'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
			}
			$ProcessExitCode = $process.ExitCode
			if ($ProcessExitCode -ne 0) 
			{
				"[RunCMD] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode)  + " when running command line:`r`n             " + $commandToRun | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
				$ProcessStdError = $process.StandardError.ReadToEnd()
				if ($ProcessStdError -ne $null)
				{
					"--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
				}
			}
		} 
		else 
		{
			if ($commandToRun -ne $null)
			{
				$StdoutOutput = Invoke-Expression $commandToRun
				if ($StdoutOutput -ne $null)
				{
					($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
				}
				else
				{
					'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
				}
				$ProcessExitCode = $LastExitCode
				if ($LastExitCode -gt 0)
				{
					"[RunCMD] Warning: Process exited with error code " + ("0x{0:X}" -f $ProcessExitCode) | writeto-stdout -InvokeInfo $MyInvocation -Color 'DarkYellow'
				}
			}
			else
			{
				'[RunCMD] Error: a null -commandToRun argument was sent to RunCMD' | writeto-stdout -InvokeInfo $MyInvocation -IsError
				$ProcessExitCode = 99
			}
		}
		
		"--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat
		
		if ($collectFiles -eq $true) 
		{	
			"[RunCMD] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
			if ($noFileExtensionsOnDescription.isPresent)
			{
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -noFileExtensionsOnDescription -renameOutput $renameOutput -InvokeInfo $MyInvocation
			} else {
				CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
			}
		}
		#RunCMD returns exit code only if -UseSystemDiagnosticsObject is used
		if ($useSystemDiagnosticsObject.IsPresent)
		{
			return $ProcessExitCode
		}
	} 
	else 
	{ 	#Background Process
		# Need to separate process name from $commandToRun:
		# 1. Try to identify a quote:
		if ($commandToRun.StartsWith("`""))
		{
			$ProcessName = $commandToRun.Split("`"")[1]
			$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
		} 
		elseif ($commandToRun.Contains(".exe"))
		# 2. No quote found - try to find a .exe on $commandToRun
		{
			$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
			$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
		}
		else
		{
			$ProcessName = "cmd.exe" 
			$Arguments = "/c `"" + $commandToRun + "`""
		}
		if ($noFileExtensionsOnDescription.isPresent)
		{
			$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -CollectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock 
		}
		else 
		{
			$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -noFileExtensionsOnDescription -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock
	}
	}
}



function Write-DiagProgress {
	Param ( [switch] $activity,
		[switch] $status
	)
    	if ($args) { $args | write-host  -foregroundcolor "yellow"}
	$input | write-host  -foregroundcolor "yellow"
	}

function Get-DiagInput {
	Param (
		$Id, $Paramater
	)

    	if ($args) { 
		$args | write-host  -foregroundcolor "darkgray"
		}
	$input | write-host  -foregroundcolor "darkgray"
}

function WriteTo-ErrorDebugReport {
	Param ( [switch] $ErrorRecord,
		[switch] $ScriptErrorText
	)
    	if ($args) { 
		$args | write-host  -foregroundcolor "yellow"
		$args | out-file $env:computername-stdout.txt -append
	}
	$input | write-host  -foregroundcolor "yellow"
	$input | out-file $env:computername-stdout.txt -append
}

function update-diagreport {
	Param ( $id, $name, $verbosity)
	if ($args) { 
		$args | write-host  -foregroundcolor "yellow"
		$args | out-file $env:computername-stdout.txt -append
		}
	$input | write-host  -foregroundcolor "yellow"
	$input | out-file $env:computername-stdout.txt -append

}


# CompressCollectFiles function
# ---------------------
# Description:
#       This function compresses files in a ZIP or CAB file, collecting these files after the ZIP file is created
#       ZIP format is way faster than CAB but - once Shell is used for ZIP files, there is no support for ZIP files on ServerCore
#       Where support for ZIP files is inexistent (like on ServerCore), function will automatically switch to CAB
#
# Arguments:
#		filesToCollect: Folder or Files that to be collected (Ex: C:\windows\*.txt). This value can also be an array.
#       DestinationFileName: Destination name for the zip file (Ex: MyZipFile.ZIP or MyCabFile.CAB)
#		fileDescription: Individual description of the zip file 
#		sectionDescription: Section description.
#       Recursive: Copy files in subfolders
#       renameOutput: Add the %ComputerName% prefix to the ZIP file name - if not existent
#       noFileExtensionsOnDescription: Do not add file extension to the file description (Default format is $fileDescription ($FileExtension))
#       Verbosity: When $collectFiles is true, $Verbosity is the verbosity level for CollectFiles function
#       DoNotCollectFile: If present, function will generate the ZIP file but it will not collect it
#       ForegroundProcess: *Only for CAB files - By default CAB files are compressed in a Background process. Use -ForegroundProcess to force waiting for compression routine to complete before continuing.
#       $NumberOfDays: Do not add files older than $NumberOfDays days to the compressed files
#		$CheckFileInUse:  If present, function will check all files if they are in-used recursively, but it will take more time and may cause some performance issues

Function CompressCollectFiles
{
	PARAM($filesToCollect,
		[string]$DestinationFileName="File.zip",
		[switch]$Recursive,
		[string]$fileDescription="File", 
		[string]$sectionDescription="Section",
		[boolean]$renameOutput=$true,
		[switch]$noFileExtensionsOnDescription,
		[string]$Verbosity="Informational",
		[switch]$DoNotCollectFile,
		[switch]$ForegroundProcess=$false,
		[int]$NumberOfDays=0,
		[switch]$CheckFileInUse
	)

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[CompressCollectFiles]" -InvokeInfo $MyInvocation
		continue
	}

	$FileFormat = [System.IO.Path]::GetExtension($DestinationFileName)
	if ($FileFormat.Length -ne 4) {$FileFormat = ".zip"}
	if (((-not (Test-Path -Path (join-path ([Environment]::SystemDirectory) "shell32.dll"))) -or ((-not (Test-Path -Path (join-path ($Env:windir) "explorer.exe"))))) -and ($FileFormat -eq ".zip"))
	{
		"[CompressCollectFiles] - File format was switched to .CAB once shell components is not present" | WriteTo-StdOut -ShortFormat
		$FileFormat = ".cab"
	}
	if ([int]$OSVersion.Major -lt 6) {"hi"}
	if ([int]$OSVersion.Major -lt 6) 
	{
		"[CompressCollectFiles] - File format was switched to .CAB once this OS does not support ZIP files" | WriteTo-StdOut -ShortFormat
		$FileFormat = ".cab"
	}

	if ($NumberOfDays -ne 0)
	{
		"[CompressCollectFiles] Restrict files older than $NumberOfDays days" | WriteTo-StdOut -ShortFormat
		$OldestFileDate = (Get-Date).AddDays(($NumberOfDays * -1))
	}

	if (($renameOutput -eq $true) -and (-not $DestinationFileName.StartsWith($ComputerName))) 
	{
		$CompressedFileNameWithoutExtension = $ComputerName + "_" + [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
	} else {
		$CompressedFileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
	}

	if (($FileFormat -eq ".cab") -and ($ForegroundProcess -eq $false) -and ($DoNotCollectFile.IsPresent))
	{
		"[CompressCollectFiles] Switching to Foreground execution as background processing requires file collection and -DoNotCollectFile iscurrently set" | WriteTo-StdOut -ShortFormat
		$ForegroundProcess = $true
	}
	
	$CompressedFileName = ($PWD.Path) + "\" + $CompressedFileNameWithoutExtension + $FileFormat

	if ($FileFormat -eq ".cab")
	{
		#Create DDF File
		$ddfFilename = Join-Path $PWD.Path ([System.IO.Path]::GetRandomFileName())
		
	    ".Set DiskDirectoryTemplate=" + "`"" + $PWD.Path + "`"" | Out-File -FilePath $ddfFilename -Encoding "UTF8";
	    ".Set CabinetNameTemplate=`"" + [IO.Path]::GetFileName($CompressedFileName) + "`""| Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	 
	    ".Set Cabinet=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set Compress=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set InfAttr=" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set FolderSizeThreshold=2000000" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxCabinetSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxDiskSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	}

	$ShellGetAllItems = {
	PARAM ($ShellFolderObj, $ZipFileName)
		if ($ShellFolderObj -is "System.__ComObject")
		{
			$ArrayResults = @()
			foreach ($ZipFileItem in $ShellFolderObj.Items())
			{
				$ArrayResults += $ZipFileItem.Path.Substring($ZipFileName.Length + 1)
				
				if ($ZipFileItem.IsFolder)
				{
					$ArrayResults += $ShellGetAllItems.Invoke((new-object -com Shell.Application).NameSpace($ZipFileItem.Path), $ZipFileName)
				}
			}
			return $ArrayResults
		}
	}

	ForEach ($pathFilesToCollect in $filesToCollect) 
	{
		"[CompressCollectFiles] Compressing " + $pathFilesToCollect + " to " + [System.IO.Path]::GetFileName($CompressedFileName) | WriteTo-StdOut -ShortFormat

		if (test-path ([System.IO.Path]::GetDirectoryName($pathFilesToCollect)) -ErrorAction SilentlyContinue) 
		{
			if ($Recursive.IsPresent) 
			{
				if (($pathFilesToCollect.Contains('*') -eq $false) -and ($pathFilesToCollect.Contains('?') -eq $false) -and [System.IO.Directory]::Exists($pathFilesToCollect))
				{
					#If the path looks like a folder and a folder with same name exists, consider that the file is a folder
					$FileExtension = '*.*'
					$RootFolder = $pathFilesToCollect
				}
				else
				{
					$FileExtension = Split-Path $pathFilesToCollect -leaf
					$RootFolder = [System.IO.Path]::GetDirectoryName($pathFilesToCollect)
				}
				if (($FileExtension -eq "*.*") -and ($FileFormat -eq ".zip") -and ($NumberOfDays -eq 0) -and ($CheckFileInUse.IsPresent -eq $false))
				{
					#Optimization to collect subfolders on ZIP files
					$FilestobeCollected = Get-ChildItem -Path $RootFolder
				} 
				else 
				{
					$FilestobeCollected = Get-ChildItem -Path $RootFolder -Include $FileExtension -Recurse
					$FilestobeCollected = $FilestobeCollected | Where-Object {$_.PSIsContainer -eq $false}
				}
			} 
			else 
			{
				#a folder without recurse, or a file without recurse, or an extension filter without recurse
				$FilestobeCollected = Get-ChildItem -Path $pathFilesToCollect | Where-Object {$_.PSIsContainer -eq $false}
			}
			
			if ((($FilestobeCollected -is [array]) -and ($FilestobeCollected.Count -gt 0)) -or ($FilestobeCollected -ne $null))
			{
				if ($NumberOfDays -ne 0)
				{
					$StringFilesExcluded = ''
					Foreach ($FileinCollection in ($FilestobeCollected | Where-Object {$_.LastWriteTime -lt $OldestFileDate}))
					{
						$StringFilesExcluded += (' ' * 10) + '- ' + ($FileinCollection.FullName) + " - Date: " + ($FileinCollection.LastWriteTime.ToShortDateString()) + "`r`n"
					}
					if ($StringFilesExcluded -ne '')
					{
						"Files not included in compressed results as they are older than " + $OldestFileDate.ToShortDateString() + ":`r`n" + $StringFilesExcluded | WriteTo-StdOut -ShortFormat
						$FilestobeCollected = $FilestobeCollected | Where-Object {$_.LastWriteTime -ge $OldestFileDate}
					}
				}
				$IsAnyFileInUse = $false
				if($CheckFileInUse.IsPresent)
				{
					$NotInUseFiles=@()
					foreach($file in $FilestobeCollected)
					{
						if((Is-FileInUse -FilePath ($file.FullName)) -eq $false)
						{
							$NotInUseFiles += $file
						}
						else
						{
							$IsAnyFileInUse = $true
							"[CompressCollectFiles] File " + $file.FullName + " is currently in use - Skipping" | WriteTo-StdOut -ShortFormat
						}
					}
					$FilestobeCollected = $NotInUseFiles
				}
				if (($FileExtension -ne "*.*") -or ($FileFormat -ne ".zip") -or ($NumberOfDays -ne 0) -or  $IsAnyFileInUse)
				{
					$SubfolderToBeCollected = $FilestobeCollected | Select-Object -Unique "Directory" | %{$_."Directory"} #Modified to work on PS 1.0.
				}
				elseif(($CheckFileInUse.IsPresent) -and ($IsAnyFileInUse -eq $false))
				{
					#Means the CheckFileInUse parameter is present but there is no file in used, So get the FilestobeCollected without recurse again
					$FilestobeCollected = Get-ChildItem -Path $RootFolder
				}
			}
			if ((($FilestobeCollected -is [array]) -and ($FilestobeCollected.Count -gt 0)) -or ($FilestobeCollected -ne $null))
			{
				
		 		switch ($FileFormat)
				{
					".zip" 
					{
						#Create file if it does not exist, otherwise just add to the ZIP file name
						$FilesToSkip = @()
						if (-not (Test-Path ($CompressedFileName))) 
						{
							Set-Content $CompressedFileName ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
						}
						else 
						{
							#Need to check file name conflicts, otherwise Shell will raise a message asking for overwrite
							if ($RootFolder -eq $null) {$RootFolder = [System.IO.Path]::GetDirectoryName($pathFilesToCollect)}
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							$FilesToBeCollectedFullPath = ($FilestobeCollected | %{$_."FullName"})
							$AllZipItems = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
							foreach ($ZipFileItem in $AllZipItems)
							{
								$FileNameToCheck = $RootFolder + "\" + $ZipFileItem
								if ($FilesToBeCollectedFullPath -contains $FileNameToCheck)
								{
									if (($FileExtension -eq "*.*") -or ([System.IO.Directory]::Exists($FileNameToCheck) -eq $false)) #Check if it is a folder, so it will not fire a message on stdout.log
									{
										#Error - File Name Conflics exist
										$ErrorDisplay = "[CompressCollectFiles] Error: One or more file name conflicts when compressing files were detected:`r`n"
										$ErrorDisplay += "        File Name   : "+ $FileNameToCheck + "`r`n"
										$ErrorDisplay += "        Zip File    : " + $CompressedFileName + "`r`n"
										$ErrorDisplay += "   File/ Folder will not be compressed."
										$ErrorDisplay | WriteTo-StdOut
									}
									$FilesToSkip += $FileNameToCheck
								}
							}
						}
						
						$ExecutionTimeout = 10 #Time-out for compression - in minutes

						$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						$InitialZipItemCount = 0
						
						if (($Recursive.IsPresent) -and (($FileExtension -ne "*.*") -or ($NumberOfDays -ne 0) -or $IsAnyFileInUse))
						{
							#Create Subfolder structure on ZIP files
							#$TempFolder = mkdir -Path (Join-Path $Env:TEMP ("\ZIP" + (Get-Random).toString()))
							$TempFolder = mkdir -Path (Join-Path $PWD.Path ("\ZIP" + [System.IO.Path]::GetRandomFileName()))
							$TempFolderObj = (new-object -com Shell.Application).NameSpace($TempFolder.FullName)
							
							foreach ($SubfolderToCreateOnZip in ($SubfolderToBeCollected | %{$_."FullName"})) #modified to support PS1.0 -ExpandProperty doesn't behave the same in PS 1.0
							{
								$RelativeFolder = $SubfolderToCreateOnZip.Substring($RootFolder.Length)
								if ($RelativeFolder.Length -gt 0)
								{
									$TempFolderToCreate = (Join-Path $TempFolder $RelativeFolder)
									MKDir -Path $TempFolderToCreate -Force | Out-Null
									"Temporary file" |Out-File -FilePath ($TempFolderToCreate + "\_DeleteMe.Txt") -Append #Temporary file just to make sure file isn't empty so it won't error out when using 'CopyHere
								}
							}
							
							#Create subfolder structure on ZIP file:
							
							foreach ($ParentTempSubfolder in $TempFolder.GetDirectories("*.*", [System.IO.SearchOption]::AllDirectories))
							{
								if (($AllZipItems -eq $null) -or ($AllZipItems -notcontains ($ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length+1))))
								{
									
									$TimeCompressionStarted = Get-Date
									$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName + $ParentTempSubfolder.Parent.FullName.Substring($TempFolder.FullName.Length))
									$InitialZipItemCount = $ZipFileObj.Items().Count
									$ZipFileObj.CopyHere($ParentTempSubfolder.FullName, $DontShowDialog)

									do
									{
										sleep -Milliseconds 100
										
										if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge 2)
										{
											$ErrorDisplay = "[CompressCollectFiles] Compression routine will be terminated due it reached a timeout of 2 minutes to create a subfolder on zip file:`r`n"
											$ErrorDisplay += "        SubFolder   : " + $RootFolder + $ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length) + "`r`n"
											$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
											$ErrorDisplay | WriteTo-StdOut
											$TimeoutOcurred = $true
										}
																
									} while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
									
									#$AllZipItems += [System.IO.Directory]::GetDirectories($ParentTempSubfolder.FullName, "*.*", [System.IO.SearchOption]::AllDirectories) | ForEach-Object -Process {$_.Substring($TempFolder.FullName.Length + 1)}
									$AllZipItems  = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
								}
							}
						}
						
						if (($ZipFileObj -eq $null) -or ($ZipFileObj.Self.Path -ne $CompressedFileName))
						{
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						}
					}
				}
		
				$FilestobeCollected | ForEach-object -process {
				
					$FileName = Split-Path $_.Name -leaf
					$FileNameFullPath = $_.FullName
					if ([System.IO.Directory]::Exists($pathFilesToCollect))
					{
						$ParentFolderName = [System.IO.Path]::GetFullPath($pathFilesToCollect)
					}
					else
					{
						$ParentFolderName = [System.IO.Path]::GetDirectoryName($pathFilesToCollect).Length
					}
					
					if (($Recursive.IsPresent) -and ([System.IO.Path]::GetDirectoryName($FileNameFullPath).Length -gt $ParentFolderName.Length))
					{
						$RelativeFolder = [System.IO.Path]::GetDirectoryName($FileNameFullPath).Substring($RootFolder.Length)
					} else {
						$RelativeFolder = ""
						$CurrentZipFolder = ""
					}
					
			 		switch ($FileFormat)
					{
						".zip" 
						{
							$TimeCompressionStarted = Get-Date
							$TimeoutOcurred = $false

							if (($FileExtension -eq "*.*") -and ([System.IO.Directory]::Exists($FileNameFullPath)))
							{
								#Check if folder does not have any file
								if (([System.IO.Directory]::GetFiles($FileNameFullPath, "*.*", [System.IO.SearchOption]::AllDirectories)).Count -eq 0)
								{
									$FilesToSkip += $FileNameFullPath
									"[CompressCollectFiles] Folder $FileNameFullPath will not be compressed since it does not contain any file`r`n"
								}
							}

							if ($RelativeFolder -ne $CurrentZipFolder)
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace((join-path $CompressedFileName $RelativeFolder))
								ForEach ($TempFile in $ZipFileObj.Items()) 
								{
									#Remove temporary file from ZIP
									if ($TempFile.Name.StartsWith("_DeleteMe")) 
									{
										$DeleteMeFileOnTemp = (Join-Path $TempFolder.FullName "_DeleteMe.TXT")
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path $DeleteMeFileOnTemp}
										$TempFolderObj.MoveHere($TempFile)
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path (Join-Path $TempFolder.FullName "_DeleteMe.TXT")}
									}
								}
								$CurrentZipFolder = $RelativeFolder
							} 
							elseif (($RelativeFolder.Length -eq 0) -and ($ZipFileObj.Self.Path -ne $CompressedFileName))
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							}
							
							if (($FilesToSkip -eq $null) -or ($FilesToSkip -notcontains $FileNameFullPath))
							{
								"             + " + $FileNameFullPath + " to " + ([System.IO.Path]::GetFileName($CompressedFileName)) + $ZipFileObj.Self.Path.Substring($CompressedFileName.Length) | WriteTo-StdOut -ShortFormat
								$InitialZipItemCount = $ZipFileObj.Items().Count
								$ZipFileObj.CopyHere($FileNameFullPath, $DontShowDialog)
						
								while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
								{
									sleep -Milliseconds 200
									
									if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge $ExecutionTimeout)
									{
										$ErrorDisplay = "[CompressCollectFiles] Compression routine will be terminated due it reached a timeout of $ExecutionTimeout minutes:`r`n"
										$ErrorDisplay += "        File Name   : $FileNameFullPath `r`n"
										$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
										$ErrorDisplay | WriteTo-StdOut
										$TimeoutOcurred = $true
									}
															
								} 
							}
						}
						".cab"
						{
							if ($RelativeFolder -ne $CurrentCabFolder)
							{
								$ListOfFilesonDDF += ".Set DestinationDir=`"" + $RelativeFolder + "`"`r`n"
								$CurrentCabFolder = $RelativeFolder
							}
							$ListOfFilesonDDF += "`"" + $FileNameFullPath + "`"`r`n" 
							$StringFilesIncluded += (' ' * 10) + '+ ' + $FileNameFullPath + "`r`n" 
						}
					}
				}	
				#Add condition to check if the $TempFolder actually exists.
				if(($TempFolder -ne $null) -and (Test-Path -Path $TempFolder.FullName)) { Remove-Item -Path $TempFolder.FullName -Recurse }
			} else {
				"[CompressCollectFiles] No files found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
			}
		} else {
			"[CompressCollectFiles] Path not found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
		}		
	} #ForEach
	
	if (($FileFormat -eq ".zip") -and (Test-Path $CompressedFileName) -and (-not $DoNotCollectFile.IsPresent))
	{
		if ($noFileExtensionsOnDescription.IsPresent)
		{
			CollectFiles -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -renameOutput ($renameOutput -eq $true) -Verbosity $Verbosity -noFileExtensionsOnDescription -InvokeInfo $MyInvocation
		}
		else
		{
			CollectFiles -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -renameOutput ($renameOutput -eq $true) -Verbosity $Verbosity -InvokeInfo $MyInvocation
		}
	}
	
	if ($FileFormat -eq ".cab")
	{					
		if ($ListOfFilesonDDF -ne $null) 
		{
			$ListOfFilesonDDF | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		    "Files to be included in " + [System.IO.Path]::GetFileName($CompressedFileName) + ":`r`n" + $StringFilesIncluded | WriteTo-StdOut -ShortFormat

			$AddToCommandLine = " > nul"
			
			if ($debug -eq $true)
			{
				"MakeCab DDF Contents: " | WriteTo-StdOut -ShortFormat
				Get-Content $ddfFilename | Out-String | WriteTo-StdOut
				$AddToCommandLine = " > 1.txt & type 1.txt"
			}
			
			if ($ForegroundProcess.IsPresent)
			{
				$commandToRun = ($env:windir + "\system32\cmd.exe /c `"`"" + $env:windir + "\system32\makecab.exe`" /f `"" + $ddfFilename + "`"$AddToCommandLine`"")
				if ($noFileExtensionsOnDescription.IsPresent -eq $true)
				{
					if ($DoNotCollectFile.IsPresent)
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription -collectFiles $false
					}
					else
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
					}
				}
				else
				{
					if ($DoNotCollectFile.IsPresent)
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -collectFiles $false
					}
					else
					{
						Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity
					}
				}
				
				if ($debug -ne $true)
				{
					Remove-Item $ddfFilename
				}
			} 
			else 
			{
				if ($debug -ne $true)
				{
					$AddToCommandLine += " & del `"$ddfFilename`""
				}
				
				$commandToRun = ($env:windir + "\system32\cmd.exe")
				$commandArguments = ("/c `"`"" + $env:windir + "\system32\makecab.exe`" /f `"" + $ddfFilename + "`"$AddToCommandLine`"")
				
				if ($noFileExtensionsOnDescription.IsPresent -eq $true)
				{
					BackgroundProcessCreate -ProcessName $commandToRun -Arguments $commandArguments -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				} 
				else 
				{
					BackgroundProcessCreate -ProcessName $commandToRun  -Arguments $commandArguments -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				}
			}
		} 
		else 
		{
			"Unable to find files to be collected" | WriteTo-StdOut
			Remove-Item $ddfFilename
		}
	} 
}


Function CheckMinimalFileVersion([string] $Binary, $RequiredMajor, $RequiredMinor, $RequiredBuild, $RequiredFileBuild, [switch] $LDRGDR, [switch] $ForceMajorCheck, [switch] $ForceMinorCheck, [switch] $ForceBuildCheck, [switch]$CheckFileExists)
{
	# -LDRGDR switch:
	#    Adds a logic to work with fixes (like Security hotfixes), which both LDR and GDR versions of a binary is deployed as part of the hotfix
	# -ForceMajorCheck switch:
	#    Usually if a fix applies to a specific OS version, the script returns $true. You can force checking the Major version by using this switch
	# -ForceMinorCheck switch:
	#    Usually if a fix applies to a specific Service Pack version, we just return $true. You can ignore always returning $true and making the actual binary check by #using this switch
	# -ForceBuildCheck switch:
	#    Usually if a fix applies to a specific OS version, we just return $true. You can ignore always returning $true and making the actual binary check by using this #switch.
	
	if (test-path -Path $Binary)

	{
		$StdoutDisplay = ''
		$FileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Binary)
		
		# If the version numbers from the binary is different than the OS version - it means the file is probably not a inbox component. 
		# In this case, set the $ForceMajorCheck, $ForceBuildCheck and $ForceBuildCheck to $true automatically
		
		if (($FileVersionInfo.FileMajorPart -ne $OSVersion.Major) -and ($FileVersionInfo.FileMinorPart -ne $OSVersion.Minor) -and ($FileVersionInfo.FileBuildPart -ne $OSVersion.Build))
		{
			$ForceBuildCheck = $true
			$ForceMinorCheck = $true
			$ForceMajorCheck = $true
		}
		
		if ($ForceMajorCheck)
		{
			$StdoutDisplay = '(Force Major Check)'
		}
		
		if ($ForceMinorCheck)
		{
			$ForceMajorCheck = $true			
			$StdoutDisplay = '(Force Minor Check)'
		}

		if ($ForceBuildCheck)
		{
			$ForceMajorCheck = $true	
			$ForceMinorCheck = $true
			$StdoutDisplay = '(Force Build Check)'
		}
		
		if ((($ForceMajorCheck.IsPresent) -and ($FileVersionInfo.FileMajorPart -eq $RequiredMajor)) -or (($ForceMajorCheck.IsPresent -eq $false) -and ($FileVersionInfo.FileMajorPart -eq $RequiredMajor)))
		{
			if ((($ForceMinorCheck.IsPresent) -and ($FileVersionInfo.FileMinorPart -eq $RequiredMinor)) -or (($ForceMinorCheck.IsPresent -eq $false) -and ($FileVersionInfo.FileMinorPart -eq $RequiredMinor)))
			{
				if (($ForceBuildCheck.IsPresent) -and ($FileVersionInfo.FileBuildPart -eq $RequiredBuild) -or (($ForceBuildCheck.IsPresent -eq $false) -and ($FileVersionInfo.FileBuildPart -eq $RequiredBuild)))
				{
					#Check if -LDRGDR was specified - in this case run the LDR/GDR logic					
					#For Windows Binaries, we need to check if current binary is LDR or GDR for fixes:
					if (($LDRGDR.IsPresent) -and ($FileVersionInfo.FileMajorPart -ge 6) -and ($FileVersionInfo.FileBuildPart -ge 6000))
					{
						#Check if the current version of the file is GDR or LDR:
						if ((($FileVersionInfo.FilePrivatePart.ToString().StartsWith(16)) -and (($RequiredFileBuild.ToString().StartsWith(16)) -or ($RequiredFileBuild.ToString().StartsWith(17)))) -or 
							(($FileVersionInfo.FilePrivatePart.ToString().StartsWith(17)) -and ($RequiredFileBuild.ToString().StartsWith(17))) -or 
							(($FileVersionInfo.FilePrivatePart.ToString().StartsWith(18)) -and ($RequiredFileBuild.ToString().StartsWith(18))) -or 
							(($FileVersionInfo.FilePrivatePart.ToString().StartsWith(20)) -and ($RequiredFileBuild.ToString().StartsWith(20))) -or 
							(($FileVersionInfo.FilePrivatePart.ToString().StartsWith(21)) -and ($RequiredFileBuild.ToString().StartsWith(21))) -or
							(($FileVersionInfo.FilePrivatePart.ToString().StartsWith(22)) -and ($RequiredFileBuild.ToString().StartsWith(22))) 
							)
						{
							#File and requests are both GDR or LDR - check the version in this case:
							if ($FileVersionInfo.FilePrivatePart -ge $RequiredFileBuild)
							{
								$VersionBelowRequired = $false
							} 
							else 
							{
								$VersionBelowRequired = $true
							}
						}
						else 
						{
							#File is either LDR and Request is GDR - Return true always:
							$VersionBelowRequired = $false
							return $true
						} 
					} 
					elseif ($FileVersionInfo.FilePrivatePart -ge $RequiredFileBuild) #All other cases, perform the actual check
					{
						$VersionBelowRequired = $false
					} 
					else 
					{
						$VersionBelowRequired = $true
					}
				} 
				else 
				{
					if ($ForceBuildCheck.IsPresent)
					{
						$VersionBelowRequired = ($FileVersionInfo.FileBuildPart -lt $RequiredBuild)
					}
					else 
					{
						"[CheckFileVersion] $StdoutDisplay $Binary version is " + (Get-FileVersionString($Binary)) + " - Required version (" + $RequiredMajor + "." + $RequiredMinor + "." + $RequiredBuild + "." + $RequiredFileBuild + ") applies to a newer Service Pack - OK" | writeto-stdout -shortformat
						return $true
					}
				}
			} 
			else 
			{
				if ($ForceMinorCheck.IsPresent)
				{
					$VersionBelowRequired =  ($FileVersionInfo.FileMinorPart -lt $RequiredMinor)
				} 
				else 
				{
					"[CheckFileVersion] $StdoutDisplay $Binary version is " + (Get-FileVersionString($Binary)) + " - and required version (" + $RequiredMajor + "." + $RequiredMinor + "." + $RequiredBuild + "." + $RequiredFileBuild + ") applies to a different Operating System Version - OK" | writeto-stdout -shortformat
					return $true
				}
			} 
		} 
		else 
		{
			if ($ForceMajorCheck.IsPresent -eq $false)
			{
				"[CheckFileVersion] $StdoutDisplay $Binary version is " + (Get-FileVersionString($Binary)) + " - and required version (" + $RequiredMajor + "." + $RequiredMinor + "." + $RequiredBuild + "." + $RequiredFileBuild + ") applies to a different Operating System Version - OK" | writeto-stdout -shortformat
				return $true
			}
			else
			{
				$VersionBelowRequired = ($FileVersionInfo.FileMajorPart -lt $RequiredMajor)
			}
		}
		
		if ($VersionBelowRequired)
		{
			"[CheckFileVersion] $StdoutDisplay $Binary version is " + (Get-FileVersionString($Binary)) + " and required version is $RequiredMajor" + "." + $RequiredMinor + "." + $RequiredBuild + "." + $RequiredFileBuild | writeto-stdout -shortformat
			return $false
		}
		else 
		{
			"[CheckFileVersion] $StdoutDisplay $Binary version is " + $FileVersionInfo.FileMajorPart + "." + $FileVersionInfo.FileMinorPart + "." + $FileVersionInfo.FileBuildPart + "." + $FileVersionInfo.FilePrivatePart + " and required version is " + $RequiredMajor + "." + $RequiredMinor + "." + $RequiredBuild + "." + $RequiredFileBuild + " - OK" | writeto-stdout -shortformat
			return $true
		}
	}
	else 
	{
		if($CheckFileExists.IsPresent)
		{
			"[CheckFileVersion] $Binary does not exist. Returning 'false' as  -CheckFileExists switch was used" | writeto-stdout -shortformat
			return $false
		}
		return $true
	}
}




Function Convert-PSObjectToHTMLTable
{
	Param ($PSObject,[switch] $FistMemberIsHeader)
	
	if ($PSObject -eq $null) {$PSObject=$_}
	
	$HeaderIncluded = $false
	foreach($p in $PSObject.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty"}) 
	{
		$Name  = $p.Name
		$Value = $p.Value
		if (($FistMemberIsHeader.IsPresent) -and ($HeaderIncluded -eq $false))
		{
			$TableString += "`t<tr><th>$Name</th><th>$Value</th></tr>`r`n"
			$HeaderIncluded = $true
		}
		else
		{
			$TableString += "`t<tr><td>$Name</td><td>$Value</td></tr>`r`n"
		}
	}
	
	return ("<table>`r`n" + $TableString + "</table>")
}





# Visibility = 1 - FTE Only
# Visibility = 2 - Partners
# Visibility = 3 - Internal
# Visibility = 4 - Public

#Support Topic IDs can be obtained here: http://sharepoint/sites/diag/scripteddiag/_layouts/xlviewer.aspx?id=/sites/diag/scripteddiag/SDP%2030/Support%20Topics%20UDE%20Table.xlsx
#ConvertTo-Xml2 function
#-------------------------
#  This function is a replacement from ConvertTo-Xml.
#  ConvertTo-Xml replaces HTML tags inside strings limiting the richness of the resulting data
#  For instance, when using ConvertTo-Xml against a string like <b>Text</b>, results on the following:
#  &lt;b&gt;Text&lt;/b&gt;
#  the ConvertTo-Xml2 is our light implementation for ConvertTo-Xml that do not make string conversion.
filter ConvertTo-Xml2
{Param ($object, [switch]$sortObject, [int] $Visibility = 4)

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[ConvertTo-Xml2]" -InvokeInfo $MyInvocation
		$Error.Clear()
		continue
	}

	if ($object -eq $null) {$object=$_}
	
	$typeName = $object.GetType().FullName
	
	if (($Visibility -ge 0) -and ($Visibility -le 3))
	{
		$VisibilityString = 'Visibility="' + $Visibility + '"'
	}
	else
	{
		$VisibilityString = ''
	}
	$XMLString = "<?xml version=`"1.0`"?><Objects $VisibilityString><Object Type=`"$typeName`">" 

	if ((($object.GetType().Name -eq "PSObject") -or ($object.GetType().Name -eq "PSCustomObject")) -and (-not $sortObject.IsPresent) ) 
	{
		foreach($p in $object.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty"}) 
		{
			$Name  = $p.Name
			$Value = $p.Value    
			$XMLString += "`t<Property Name=`"$Name`">$Value</Property>`r`n"
		}
	} 
	elseif ($object -is [System.String])
	{
		$XMLString += $object
	}
	else
	{
		foreach ($p in $object |Get-Member -type *Property)
		{
			$Name  = $p.Name
			$Value = $Object.$Name    
			$XMLString += "`t<Property Name=`"$Name`">$Value</Property>`r`n"
		}
	}
	$XMLString += "</Object></Objects>"

	[xml] $XMLString
}

#Obtain file version information for files located under Windows folder.
#For Windows Components the ProductVersion and FileVersion properties of a file Version Info is incorrect
#When the FileVersion does not start with the concatenated string({FileMajorPart}.{FileMinorPart}.{FileBuildPart}.{FilePrivatePart}), return the concatenated string
#Else return the FileVersion String
Function Get-FileVersionString(
	[string]$Path)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Get-FileVersionString]An error occurred while getting version info on the file $Path"
		continue
	}
	if([System.IO.File]::Exists($Path))
	{
		$fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
		if($fileInfo -ne $null)
		{
			if(($fileInfo.FileMajorPart -ne 0) -or ($fileInfo.FileMinorPart -ne 0) -or ($fileInfo.FileBuildPart -ne 0) -or ($fileInfo.FilePrivatePart -ne 0))
			{
				$concatenatedVersion=$fileInfo.FileMajorPart.ToString() + '.' + $fileInfo.FileMinorPart.ToString() + '.' + $fileInfo.FileBuildPart.ToString() + '.' + $fileInfo.FilePrivatePart.ToString()
				if(($fileInfo.FileVersion -ne $null) -and ($fileInfo.FileVersion.StartsWith($concatenatedVersion)))
				{
					return $fileInfo.FileVersion
				}
				else
				{
					return $concatenatedVersion
				}
			}
			else
			{
				"[Get-FileVersionString] The file $Path is unavailable" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
			}
		}
		else
		{
			"[Get-FileVersionString] The file $Path is unavailable" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
		}
	}
	else
	{
		"[Get-FileVersionString] The file $Path does not exist" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
	}
}



##################################################################################################

function stopanddeletealltraces {
	$foo =logman | Select-Object
	foreach ($f in $foo) { if($f -match "(wapdebug-\d+).*")  { logman stop $matches[1]}}
	foreach ($f in $foo) { if($f -match "(wapdebug-\d+).*")  { logman delete $matches[1]}}

}



######################################################################
#
# Navigation
#
##################################
function home {
	C:
	cd $env:homepath
}
function docs{
	C:
	cd $env:homepath\documents
}
function t {
	C:
	cd c:\temp
}
function sdp {
	d:
	cd d:\sdp\dev\systemcenter
}

if (Test-path c:\temp\dc_vmmutils.ps1) { . c:\temp\dc_vmmutils.ps1}
if (Test-path C:\temp\dc_asrutils.ps1) { . C:\temp\dc_asrutils.ps1}
