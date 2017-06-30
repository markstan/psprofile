"Loading utitilites" | WriteTo-StdOut -ShortFormat


#############################################################################
#
#  Check-FreeDiskSpace
#  
#  Returns one of 3 states:
#                    * OK = enough free space
#                    * Ignore = user override low space warning
#                    * Exit = user chose to cancel SDP
#
#
#
#
#
#############################################################################

function Check-FreeDiskspace {
    [string]$Resp = "OK"
    [float]$FreeSpace = [math]::round($pwd.Drive.Free/1GB,2)
    [int]$LowSpaceLimit = 2

    "Free space on $($pwd.Drive.Root) = $FreeSpace GB" | WriteTo-StdOut -ShortFormat


    if ($FreeSpace -lt $LowSpaceLimit) {
            
            $Resp = Get-DiagInput -Id LowSpaceWarning  -Parameter @{"DriveLetter"=$(($Pwd.Drive.Root).Replace("\","")); "DiskSpace"=$([math]::Round(($pwd.Drive.Free/1GB),2))}
            "Low disk action = $Resp" | WriteTo-StdOut -ShortFormat
        }
    if ($Resp -eq "Ignore") { "User chose to override and ignore low space warning" | WriteTo-StdOut -ShortFormat}

    Return $Resp

    }
    

function Check-DataSize {
    Param ([string]$FolderName = $pwd,
           [switch]$Recurse 

    )

    
     if ($Recurse) {
        $size = [math]::Round($(Get-ChildItem $FolderName -Recurse| Measure-Object -property length -sum ).Sum/1GB,2)
        }
     else {
        $size = [math]::Round($(Get-ChildItem $FolderName | Measure-Object -property length -sum ).Sum/1GB,2)
        }
     
    return $size

}

#############################################################################
#
#  IsASRServer
#  
#  Returns true if services are installed, false otherwise
#
#
#
#
#
#############################################################################

function IsASRServer {
    Param ([String]$ASRServer = $env:ComputerName)

    [boolean]$isDRA = $false

    $nil = if ((Get-Service dra -ComputerName $ASRServer -ErrorAction SilentlyContinue ) -or (Get-Service obengine -ComputerName $ASRServer -ErrorAction SilentlyContinue)) {
        $isDRA = $true
        }

    return $isDRA


}


###########################################################################################################
#
# Get-InstDirConf - returns installation directory of ASR roles
#
# Inputs:  $Role - must be either "Agent","Amethyst", or "vContinuum".  Defaults to Agent if no params passed
#
# Outputs:  $InstDetails[] - array with 3 members:
# 
#                    $InstDetails[0]     = 0 for not present, 1 for present
#                    $InstDetails[1]     = installation directory from registy (InstallDirectory)
#                    $InstDetails[2]     = Canary file to check for to verify role and check configuration
#
#
###########################################################################################################


function Get-InstDirConf {
    Param (
        [ValidateSet("Agent","Amethyst","vContinuum")][String]$Role= "Agent"
    )

    [string[]]$InstDetails = @("","","")
    [string]$RoleNumber = 5
    
    "Testing role $Role on $computername" | WriteTo-StdOut -ShortFormat

    #Setting Role number
    switch( $Role )
    {
     "Agent" {
                    $RoleNumber = "5";
             }
     
     "vContinuum" {
                    $RoleNumber = "6";
                }
      "Amethyst"  {
                    $RoleNumber = "9";
                  }
    }
    if ($OSArchitecture -eq "AMD64")
    {
        $RegKey = "HKLM:\SOFTWARE\Wow6432Node\InMage Systems\Installed Products\" + $RoleNumber;
    }
    else
    {
        $RegKey = "HKLM:\SOFTWARE\InMage Systems\Installed Products\" + $RoleNumber;
    }
    if (test-path $RegKey) 
    {


        "Getting $RegKey properties" | WriteTo-StdOut -ShortFormat
        $InstDetails[1] = (Get-ItemProperty $RegKey).InstallDirectory
        switch( $Role )
        {
         "Agent" {
                    $InstDetails[2] = $InstDetails[1] + "\Application Data\etc\drscout.conf"
         }
     
         "vContinuum" {
                        $InstDetails[2] = $InstDetails[1] + "\vContinuum.exe"
         }
          "Amethyst"  {
                        $InstDetails[2] = $InstDetails[1] + "\etc\amethyst.conf"
          }
        }    
        "$InstDetails[1] and $InstDetails[2] detected" | WriteTo-StdOut -ShortFormat
    }
    else {
        "No $RegKey found on $computername" | WriteTo-Stdout -ShortFormat
        
         #legacy 
        if ($Role -eq "Amethyst" ) {
             $InstDetails[1] = "C:\home\svsystems"
             $InstDetails[2] = "C:\home\svsystems\etc\amethyst.conf"

        }
    }

    # if the second param of $instdetails is not set, we did not find the role
    if ($($InstDetails[1]) -ne "" ) {
        if (Test-Path $InstDetails[2]) { $InstDetails[0] = "1"}
    }
    else {$InstDetails[0] = "0"}
    
    return $InstDetails
}


#############################################################################
#
#  Get-ASRTools
#  
#  Check for presence of ASR troubleshooting tools
#
#
#
#############################################################################

function Get-ASRTools {
            [string]$ToolsPath = "C:\Tools"
            Do
            {
                $ToolsPath = Get-DiagInput -Id DownloadTools -Parameter @{"toolsfolder"=$ToolsPath}
        
                if (Test-Path $ToolsPath)
                {
                  if ((Test-Path $ToolsPath\plink.exe) -and (Test-Path $ToolsPath\pscp.exe))  
                  {			
                    try {
                        Copy-Item $ToolsPath\plink.exe $pwd
                        Copy-Item $ToolsPath\pscp.exe $pwd 
                        }
                    catch {
                        "Unable to copy $ToolsPath\pscp.exe and $ToolsPath\plink.exe to $pwd" | WriteTo-StdOut -ShortFormat
                    }
                  }
                  else
                  {
                        Get-DiagInput -Id ToolsNotFound -Parameter @{"toolsfolder"=$ToolsPath}
                  }	
                }
                else
                {					
                    Get-DiagInput -Id ToolsFolderNotFound -Parameter @{"toolsfolder"=$ToolsPath}
                }
            }until ((Test-Path $ToolsPath\plink.exe) -and (Test-Path $ToolsPath\pscp.exe))
}


# Return install directory and version based on role

function Get-RoleDetails {
    Param ([String]$ASRRole)

        [String] $RegRoot = ""
        switch ($ASRRole) {
            "Agent"      { $RegRoot = "HKLM:SOFTWARE\Wow6432Node\InMage Systems\Installed Products\5" }  # VX Volume Replication Service
            "vContinuum" { $RegRoot = "HKLM:SOFTWARE\Wow6432Node\InMage Systems\Installed Products\6" } 
            "Amethyst"   { $RegRoot = "HKLM:SOFTWARE\Wow6432Node\InMage Systems\Installed Products\9" }  # CX Configuration Server
            }

        "RegRoot = $RegRoot" | WriteTo-StdOut -ShortFormat
        if (Test-Path $RegRoot -ErrorAction SilentlyContinue) {
            $regKeyValues = Get-ItemProperty $RegRoot
            $RoleDetails = @{
                InstallPath = $regKeyValues.installdirectory
                ProductName = $regKeyValues.Product_Name 
                Version =     $regKeyValues.Version
                VersionNumber =     $($regKeyValues.Version.Split('.'))[0]
                # Pushinstall for Amethyst
                PushInstallSvc = Join-Path $($regKeyValues.installdirectory)  "PushInstallSvc"
            }
        
                    # older versions may have installpath rather than installdirectory reg value
                    if ($regKeyValues.InstallDirectory)
                    {                    
                        $RoleDetails.installPath =  $regKeyValues.InstallDirectory

                    }
                    elseif ($regKeyValues.installPath) {
                        $RoleDetails.installPath = $regKeyValues.InstallPath
                    }
                    else         # final try.  we should never get here.  something happened to the registry
                    {
                        "Warning, no installation registry path found" | WriteTo-StdOut -ShortFormat
                        if (Test-Path "c:\home\svsystems" -ErrorAction SilentlyContinue) {
                            $RoleDetails.installPath = "c:\home\svsystems"
                        }
                        elseif (Test-Path "C:\Program Files (x86)\Microsoft Azure Site Recovery\home\svsystems" -ErrorAction SilentlyContinue) {
                            $RoleDetails.installPath = "C:\Program Files (x86)\Microsoft Azure Site Recovery\home\svsystems"
                        }
                        else {
                            "FATAL ERROR:  no svsystems folder found" | WriteTo-StdOut -ShortFormat
                        }

                  }
                  Return $RoleDetails
              }  
        else { "Fatal error  - registry path not found.  $ASRRole is not installed" |WriteTo-StdOut -ShortFormat}


}

# Return if server is PS, CS, or MT
#
# Inputs - it is the responsibility of the caller to verify that we are on an amethyst server
Function Get-ASRRoles {
    Param ([string]$RootDir = "C:\Program Files (x86)\Microsoft Azure Site Recovery\home\svsystems" )
    
    $ConfFile = Join-Path $RootDir "etc\amethyst.conf"
    $ConfFile
             #   string element = "CX_TYPE";
             #   validateFlag = validateType(filePath, element, serverType);

}

# True if ASR Hyper-V server, false otherwise
function Test-IsASRHyperVServer {
    if  (    # Hyper-V with Agent
        ([bool](Get-Service vmms -ErrorAction SilentlyContinue) -and [bool](Get-Service dra -ErrorAction SilentlyContinue)   
       )
  )      { $true  }
    else { $false }    
}


# True if default install of CS/PS
function Test-IsASRPSCS {
    if  (    # cx and tman = default install
        [bool](Get-Service cxprocessserver -ErrorAction SilentlyContinue) -and [bool](Get-Service tmansvc -ErrorAction SilentlyContinue)
       )
         { $true  }
    else { $false }    
}

# True if default install Physical Source Server
function Test-IsASRSourceServer {
    if  (    # Azure Site Recovery VSS Provider, frsvc, InMage Scout Application Service, svagents
          (Get-Service | where {$_.Name -match "Azure Site Recovery VSS Provider|frsvc|InMage Scout Application Service|svagents"}).Count -eq 4)
         { $true  }
    else { $false }    
}




Filter WriteTo-ErrorDebugReport
(
    [string] $ScriptErrorText, 
    [System.Management.Automation.ErrorRecord] $ErrorRecord = $null,
    [System.Management.Automation.InvocationInfo] $InvokeInfo = $null,
    [switch] $SkipWriteToStdout
)
{

    trap [Exception] 
    {
        $ExInvokeInfo = $_.Exception.ErrorRecord.InvocationInfo
        if ($ExInvokeInfo -ne $null)
        {
            $line = ($_.Exception.ErrorRecord.InvocationInfo.Line).Trim()
        }
        else
        {
            $Line = ($_.InvocationInfo.Line).Trim()
        }
        
        if (-not ($SkipWriteToStdout.IsPresent))
        {
            "[WriteTo-ErrorDebugReport] Error: " + $_.Exception.Message + " [" + $Line + "].`r`n" + $_.StackTrace | WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat -IsError -AdditionalFileName $pwd\exceptions.txt
             $ErrorRecord.ScriptStackTrace | WriteTo-StdOut -ShortFormat -noHeader -AdditionalFileName $pwd\exceptions.txt     }
        continue
    }

    if (($ScriptErrorText.Length -eq 0) -and ($ErrorRecord -eq $null)) {$ScriptErrorText=$_}

    if (($ErrorRecord -ne $null) -and ($InvokeInfo -eq $null))
    {
        if ($ErrorRecord.InvocationInfo -ne $null)
        {
            $InvokeInfo = $ErrorRecord.InvocationInfo
        }
        elseif ($ErrorRecord.Exception.ErrorRecord.InvocationInfo -ne $null)
        {
            $InvokeInfo = $ErrorRecord.Exception.ErrorRecord.InvocationInfo
        }
        if ($InvokeInfo -eq $null)
        {			
            $InvokeInfo = $MyInvocation
        }
    }
    elseif ($InvokeInfo -eq $null)
    {
        $InvokeInfo = $MyInvocation
    }

    $Error_Summary = New-Object PSObject
    
    if (($InvokeInfo.ScriptName -ne $null) -and ($InvokeInfo.ScriptName.Length -gt 0))
    {
        $ScriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
    }
    elseif (($InvokeInfo.InvocationName -ne $null) -and ($InvokeInfo.InvocationName.Length -gt 1))
    {
        $ScriptName = $InvokeInfo.InvocationName
    }
    elseif ($MyInvocation.ScriptName -ne $null)
    {
        $ScriptName = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
    }
    
    $Error_Summary_TXT = @()
    if (-not ([string]::IsNullOrEmpty($ScriptName)))
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Script" -Value $ScriptName 
    }
    
    if ($InvokeInfo.Line -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value ($InvokeInfo.Line).Trim()
        $Error_Summary_TXT += "Command: [" + ($InvokeInfo.Line).Trim() + "]"
    }
    elseif ($InvokeInfo.MyCommand -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value $InvokeInfo.MyCommand.Name
        $Error_Summary_TXT += "Command: [" + $InvokeInfo.MyCommand.Name + "]"
    }
    
    if ($InvokeInfo.ScriptLineNumber -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Line Number" -Value $InvokeInfo.ScriptLineNumber
    }
    
    if ($InvokeInfo.OffsetInLine -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Column  Number" -Value $InvokeInfo.OffsetInLine
    }

    if (-not ([string]::IsNullOrEmpty($ScriptErrorText)))
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Additional Info" -Value $ScriptErrorText
    }
    
    if ($ErrorRecord.Exception.Message -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Error Text" -Value $ErrorRecord.Exception.Message
        $Error_Summary_TXT += "Error Text: " + $ErrorRecord.Exception.Message
    }
    if($ErrorRecord.ScriptStackTrace -ne $null)
    {
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Stack Trace" -Value $ErrorRecord.ScriptStackTrace
    }
    
    $Error_Summary | Add-Member -MemberType NoteProperty -Name "Custom Error" -Value "Yes"

    if ($ScriptName.Length -gt 0)
    {
        $ScriptDisplay = "[$ScriptName]"
    }
    
    $Error_Summary | ConvertTo-Xml | update-diagreport -id ("ScriptError_" + (Get-Random)) -name "Script Error $ScriptDisplay" -verbosity "Debug"
    if (-not ($SkipWriteToStdout.IsPresent))
    {
        "[WriteTo-ErrorDebugReport] An error was logged to Debug Report: " + [string]::Join(" / ", $Error_Summary_TXT) | WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat -IsError -AdditionalFileName $pwd\exceptions.txt
        $ErrorRecord.ScriptStackTrace | WriteTo-StdOut -ShortFormat -noHeader -AdditionalFileName $pwd\exceptions.txt
        $ErrorRecord | fl * | Out-File $pwd\exceptions.txt -Append
    }
    $Error_Summary | fl * | Out-String | WriteTo-StdOut -DebugOnly -IsError
}




