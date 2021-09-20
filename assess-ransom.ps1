#requires -version 3

<#

    TestRansom File: Assess-Ransom.ps1
    Author: Jim Shakespear (@jshake-spear)
    Beta version 0.3: Nov 18, 2019
    Quick Notes for use:
    Use the Get-Help [Function-Name] to get info about the modules.
    Probably needs more documentation, but No files are harmed when running functions, except maybe the Apply-Wallpaper doesn't revert properly.

    Functions:
    isadmin = Checks is context is running with Elevated Privileges
    Gather-Files = Takes an array of Paths and array of extensions and looks for those files. Pipe to | Export-CSV for reporting information. Has default paths and extensions in place for common locations.
    Find-SharedDrivesCU = List the mapped drive share paths for the Current User
    Find-SharedDrivesAU = Runs best in Elevated prompt and will find all active users mapped drive shares
    Test-WriteFile = Tests whether or not a file can be written to. Does this in a way that does not modify the file in any way.
    Build-Wallpaper = Finds the current dimensions of the current Wallpaper and builds an image with those dimensions with added text for alerting the user of a ransom
    Apply-Wallpaper = Attempts to apply a wallpaper based on an Image path.
    Alert-User = Used for pop-up window with message for user. Maybe uses an .aybabtu extension (All Your Base Are Belong To Us)
    Involve-UserRansom = Provides a GUI with progress bar for the end user to "see" that their machine is being ransomed.

    Planned functions/ideas:
    Upload-Report = Takes the output of Gather-Files and uploads to a server to dump into a MySQL database for analysis.
    Ransom-Path = Only changes file extensions on all documents found on the Desktop of the computer (without recursion). Must have a -revert parameter to easily fix.
        Might need to put a note in the location for the user to get instructions that does not get changed.
    Plant-launcher = Creates or places an executable file in the location specified so that perhaps other users may open to ransom their computer


#>

#https://stackoverflow.com/questions/17605364/how-can-i-use-write-progress-in-a-pipeline-function
function Show-ProgressV3{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [PSObject[]]$InputObject,
        [string]$Activity = "Processing items"
    )

        [int]$TotItems = $Input.Count
        [int]$Count = 0

        $Input|foreach {
            $_
            $Count++
            [int]$percentComplete = ($Count/$TotItems* 100)
            Write-Progress -Activity $Activity -PercentComplete $percentComplete -Status ("Working - " + $percentComplete + "% of " + $TotItems + " Files")
        }
}

function isadmin
 {
 #Returns true/false
   ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
 }
 
 function Sample-Extensions{
 <#
        .SYNOPSIS

            This function gathers n Number of files and provides a sample of the types of files found.

        .PARAMETER samplesize

            Integer of how many files to sample.

        .PARAMETER samplesize

            Integer of how many files to sample.

        .PARAMETER greaterthan

            For the report, the count must be greater than this integer. Default is greater than 1.

        .PARAMETER

            Must be a string or an array of exclude strings. Default is none. Example is @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")

        .PARAMETER Paths

            Must be an array of Paths. By default, uses @("C:\Users\*\Documents","C:\Users\*\Dropbox","C:\Users\*\Desktop","C:\Users\*\OneDrive","C:\Users\*\Box Sync")

    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipelineByPropertyName,ValueFromPipeline=$True)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('folder')]
        [String[]]
        $Paths = @("C:\Users\*\Documents","C:\Users\*\Dropbox","C:\Users\*\Desktop","C:\Users\*\OneDrive","C:\Users\*\Box Sync"),

        [Alias('n')]
        [Alias('sample')]
        [int]
        $samplesize = 100,

        [Alias('gt')]
        [Alias('greater')]
        [int]
        $greaterthan = 1,

        [Alias('x')]
        [Alias('exclude')]
        [string[]]
        $ExcludeExtensions = ""
    )

    Write-Host "Gathering File List, Please wait. . ." -InformationAction Continue
    $Files = Get-ChildItem -Path $Paths -Exclude $ExcludeExtensions -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First $samplesize
    Write-Host "Found $($Files.count). Processing files for report. . ." -InformationAction Continue
    
    Write-Host "`n`nReport Summary" -InformationAction Continue
    $summary = $Files | Group-Object Extension -NoElement | Select-Object Name, Count | ? {$_.count -gt $greaterthan} | Sort-Object -Property Count -Descending | Out-String
    Write-Host "$($summary)" -InformationAction Continue
}

function Gather-Files{
    <#
        .SYNOPSIS

            This function gathers all the files in an array of paths and file extensions. For reporting, I'd suggest piping to Export-CSV like so: 'Gather-Files | Export-CSV -Path .\filename.csv -NoTypeInformation'

        .PARAMETER fileExtensions

            Must be an array of extensions. By default, uses @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff","*.acc*","*.laccdb")

        .PARAMETER Paths

            Must be an array of Paths. By default, uses @("C:\Users\*\Documents","C:\Users\*\Dropbox","C:\Users\*\Desktop","C:\Users\*\OneDrive","C:\Users\*\Box Sync")

    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipelineByPropertyName,ValueFromPipeline=$True)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('folder')]
        [String[]]
        $Paths = @("C:\Users\*\Documents","C:\Users\*\Dropbox","C:\Users\*\Desktop","C:\Users\*\OneDrive","C:\Users\*\Box Sync"),

        [Alias('extensions')]
        [String[]]
        $fileExtensions = @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff","*.acc*","*.laccdb"),

        [Alias('progress')]
        [switch]
        $showProgress
    )

    $startTime = (Get-Date)
    Write-Host "Gathering File List, Please wait. . . Started at $startTime" -InformationAction Continue
    
    if ($showProgress -eq $true){
	Write-Host "-ShowProgress switch enabled, expect process to take 4 or more times longer" -InformationAction Continue
        $Files = Get-ChildItem -Path $Paths -Include $fileExtensions -Recurse -Force -ErrorAction SilentlyContinue | Show-ProgressV3 -Activity "Processing Files" | Select-Object Name, Extension, @{n="UserWritable";e={Test-WriteFile -Path $_.FullName}}, @{Name="Path";Expression={$_.FullName}}, @{n="SizeKB";e={[string]::Format("{0:0.00} kB", $_.length/1KB)}}, @{n="Computername";e={$env:COMPUTERNAME}}, @{n="AsUser";e={$env:Username}}    
    } else {
	Write-Host "-ShowProgress switch disabled, running at full speed!" -InformationAction Continue
        $Files = Get-ChildItem -Path $Paths -Include $fileExtensions -Recurse -Force -ErrorAction SilentlyContinue | Select-Object Name, Extension, @{n="UserWritable";e={Test-WriteFile -Path $_.FullName}}, @{Name="Path";Expression={$_.FullName}}, @{n="SizeKB";e={[string]::Format("{0:0.00} kB", $_.length/1KB)}}, @{n="Computername";e={$env:COMPUTERNAME}}, @{n="AsUser";e={$env:Username}}    
    }

    $endTime = (Get-Date)
    Write-Host $('File Processing Duration: {0:mm} min {0:ss} sec' -f ($endTime-$startTime)) -InformationAction Continue
    Write-Host "Gathered list of $($Files.count) files" -InformationAction Continue
    
    #Generate Output of files found to screen, but not pipeline
    Write-Host "`n`nReport Summary" -InformationAction Continue
    $summary = $Files | Group-Object Extension -NoElement | Select-Object Name, Count | Sort-Object -Property Count -Descending | Out-String
    Write-Host "$($summary)" -InformationAction Continue

    return $Files

}

function Test-WriteFile{
    <#
        .SYNOPSIS

            This function Attempts to open a file as writeable then immediately closes without writing to the file.

        .PARAMETER fileExtensions

            Must be an array of extensions. By default it searches for the first file it finds, but if you want to select specific extensions to search for, and example parameter is @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")

    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipelineByPropertyName,ValueFromPipeline=$True,Mandatory=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('folder')]
        [String[]]
        $Path,

        [Alias('extensions')]
        [String[]]
        $fileExtensions = @("*")
    )

    process {
        Try {
            $testwrite = Get-ChildItem -Path $Path -Include $fileExtensions -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -f 1
            #$testwrite
            [io.file]::OpenWrite($testwrite).close()
            Write-Information "Successfully writes $testwrite"
            #$testwrite
            return $true
        }
        Catch {
            Write-Information "Unable to write to output file $testwrite"
            return $false
        }
    }

}
