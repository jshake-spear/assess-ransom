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

Function Get-RegistryKeyPropertiesAndValues{

  <#

   .Synopsis

    This function accepts a registry path and returns all reg key properties and values

   .Description

    This function returns registry key properies and values.

   .Example

    Get-RegistryKeyPropertiesAndValues -path HKCU:\Volatile Environment

    Returns all of the registry property values under the \volatile environment key

   .Parameter path

    The path to the registry key

   .Notes

    NAME:  Get-RegistryKeyPropertiesAndValues

    AUTHOR: ed wilson, msft

    LASTEDIT: 05/09/2012 15:18:41

    KEYWORDS: Operating System, Registry, Scripting Techniques, Getting Started

    HSG: 5-11-12

   .Link

     Http://www.ScriptingGuys.com/blog

 #Requires -Version 2.0

 #>

 Param(

  [Parameter(Mandatory=$true)]

  [string]$path)

 Push-Location

 Set-Location -Path $path

 Get-Item . |

 Select-Object -ExpandProperty property |

 ForEach-Object {

 New-Object psobject -Property @{property=$_;

    Value = (Get-ItemProperty -Path . -Name $_).$_}}

 Pop-Location

} #end function Get-RegistryKeyPropertiesAndValues

function isadmin
 {
 #Returns true/false
   ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
 }

function Gather-Files{
    <#
        .SYNOPSIS

            This function gathers all the files in an array of paths and file extensions. For reporting, I'd suggest piping to Export-CSV like so: 'Gather-Files | Export-CSV -Path .\filename.csv -NoTypeInformation'

        .PARAMETER fileExtensions

            Must be an array of extensions. By default, uses @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")

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
        $fileExtensions = @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")
    )

    Write-Host "Gathering File List, Please wait. . ." -InformationAction Continue
    $Result = Get-ChildItem -Path $Paths -Include $fileExtensions -Recurse -Force -ErrorAction SilentlyContinue | Select-Object Name, Extension, @{n="UserWritable";e={Test-WriteFile -Path $_.FullName}}, @{Name="Path";Expression={$_.FullName}}, @{n="SizeKB";e={[string]::Format("{0:0.00} kB", $_.length/1KB)}}, @{n="Computername";e={$env:COMPUTERNAME}}, @{n="AsUser";e={$env:Username}}
    Write-Host "Gathered list of $($Result.count) files" -InformationAction Continue

    #Generate Output of files found to screen, but not pipeline
    Write-Host "`n`nReport Summary" -InformationAction Continue
    $summary = $Result | Group-Object Extension -NoElement | Select-Object Name, Count | Sort-Object -Property Count -Descending | Out-String
    Write-Host "$($summary)" -InformationAction Continue

    return $Result

}

function Find-SharedDrivesCU {
    <#
        .SYNOPSIS

            This function lists the drives that are mounted as shares.

    #>

    if(isadmin -eq $true){
        Write-Warning "Running as Administrator context will only show drives mounted in an elevated session as the current user.`nPlease use Find-SharedDrivesAU for this session."
    }

    Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot -notlike ""} | Select-Object -ExpandProperty DisplayRoot

}

function Find-SharedDrivesAU {
    <#
        .SYNOPSIS

            This function lists the drives that are mounted as shares for all Active users on a computer. This requires Administrative Privileges.

    #>

    [CmdletBinding()]
    param(

        [Alias('aggressive')]
        [switch]
        $typedpaths
    )


    $ActiveHKEYUsers = Get-ChildItem -Path Registry::HKEY_USERS | Where-Object {$_.Name -notmatch '\bS-1-5-18\b|\bS-1-5-19\b|\bS-1-5-20\b|^*.DEFAULT\b|^.*_Classes$'}
    $sharedDrives = @()
    $explorerDrives = @()
    $typedPathUNC

    foreach ($user in $ActiveHKEYUsers){
        $drive = Get-ChildItem -Path "Registry::$($user.Name)\Network" | Get-ItemProperty | Select-Object RemotePath
        #get All drives mounted in Explorer
        #HKEY_USERS\*SID*\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        $ndrive = Get-ChildItem -Path "Registry::$($user.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ErrorAction SilentlyContinue| Select-Object @{n="Name"; e={$_.PSChildName -replace "#","\"}} | Where-Object {$_.Name -match '^\\.*'}
        $tp = Get-RegistryKeyPropertiesAndValues -path "registry::$($user.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue | Where-Object {$_.value -match '^\\'}
        $sharedDrives += New-Object psobject -Property @{
            Path = $drive | Select-Object -ExpandProperty RemotePath
            UserName = Get-ItemProperty -Path "Registry::$($user.Name)\Volatile Environment" -Name Username -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Username
        }
        foreach ($unc in $ndrive){
            $explorerDrives += New-Object psobject -Property @{
                Path = $unc | Select-Object -ExpandProperty Name
                UserName = Get-ItemProperty -Path "Registry::$($user.Name)\Volatile Environment" -Name Username -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Username
            }
        }
        if($typedpaths){
            foreach ($tpunc in $tp){
            $explorerDrives += New-Object psobject -Property @{
                Path = $tpunc | Select-Object -ExpandProperty Value
                UserName = Get-ItemProperty -Path "Registry::$($user.Name)\Volatile Environment" -Name Username -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Username
            }
        }
        }
    }

    $sharedDrives = $sharedDrives | Where-Object {$_.Path}
    $sharedDrives
    $explorerDrives = $explorerDrives | Where-Object {$_.Path}
    $explorerDrives
    #Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot -notlike ""} | Select-Object -ExpandProperty DisplayRoot


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

function Build-Wallpaper{
<#
        .SYNOPSIS

            Builds a Wallpaper based on the current dimensions of the currently applied wallpaper.

    #>

    [CmdletBinding()]
    param(
        [Alias('Top')]
        [String]
        $TopText,

        [Alias('Middle')]
        [String]
        $MiddleText = "Contact your IT department for further instructions",

        [Alias('Bottom')]
        [String]
        $BottomText
    )

    add-type -AssemblyName System.Drawing
    $wallpaperPath = Get-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name WallPaper
    $wpImg = New-Object System.Drawing.Bitmap "$($wallpaperPath.WallPaper)"

    #write-host "Width $($wpImg.Width), Height $($wpImg.Height), Text Length $($MiddleText.Length)"

    New-Item -Path "$($env:AppData + "\Microsoft\Windows\Themes\USHE\")" -ItemType "directory" -ErrorAction SilentlyContinue

    $filename = "$($env:AppData + "\Microsoft\Windows\Themes\USHE\")USHE.bmp"
    if (Test-Path -Path "$($env:AppData + "\Microsoft\Windows\Themes\USHE\")USHE.bmp"){ Remove-Item "$($env:AppData + "\Microsoft\Windows\Themes\USHE\")USHE.bmp"}
    $newWp = new-object System.Drawing.Bitmap $wpImg.Width,$wpImg.Height
    $font = new-object System.Drawing.Font Consolas,48
    $brushBg = [System.Drawing.Brushes]::Yellow
    $brushFg = [System.Drawing.Brushes]::Black
    $graphics = [System.Drawing.Graphics]::FromImage($newWp)
    $graphics.FillRectangle($brushBg,0,0,$newWp.Width,$newWp.Height)
    $graphics.DrawString($TopText,$font,$brushFg,$($wpImg.Width / 2 - ($TopText.Length * 15)), 50)
	$graphics.DrawString($MiddleText,$font,$brushFg,$($wpImg.Width / 2 - ($MiddleText.Length * 15)),$($wpImg.Height / 2 - 50))
	$graphics.DrawString($BottomText,$font,$brushFg,$($wpImg.Width / 2 - ($BottomText.Length * 15)),$($wpImg.Height - 200))
    $graphics.Dispose()
    $newWp.Save($filename)
    return $filename

}

function Apply-Wallpaper{

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipelineByPropertyName,ValueFromPipeline=$True)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('image')]
        [String]
        $imgPath,

        [Alias('changeback')]
        [switch]
        $revert
    )

    $wallpaperPath = Get-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name WallPaper
    $setwallpapersrc = @"
using System.Runtime.InteropServices;
public class wallpaper
{
public const int SetDesktopWallpaper = 20;
public const int UpdateIniFile = 0x01;
public const int SendWinIniChange = 0x02;
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
public static void SetWallpaper ( string path )
{
SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
}
}
"@
    Add-Type -TypeDefinition $setwallpapersrc


    if ($wallpaperPath.WallPaper -eq "$($env:AppData + "\Microsoft\Windows\Themes\USHE\")USHE.png"){
        Write-Host "USHE Wallpaper is already applied."
    }
    if ($revert -eq $true){
        $revertWp = Get-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name WallPaperBackup
        if($revertWp.Wallpaper -eq $wallpaperPath.Wallpaper){
            Write-Host "Wallpaper was already reverted. Please check the registry in HKCU\Control Panel\Desktop for troubleshooting."
        }else{
            [wallpaper]::SetWallpaper("$revertWp.Wallpaper")
            Write-Host "Reverting Wallpaper"
        }

        #set-itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaper -value "$($revertWp.WallPaper)"
        #Remove-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name WallPaperBackup

    }else {

         try{
            set-itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaperBackup -value "$($wallpaperPath.WallPaper)"
            [wallpaper]::SetWallpaper("$imgPath")
            #set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -name BackgroundType -value 0
            Write-Host "New Wallpaper should be applied"

             #set-itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaperBackup -value "$($wallpaperPath.WallPaper)"
             #set-itemproperty -path "HKCU:\Control Panel\Desktop" -name WallPaper -value $imgPath
             #Sleep -seconds 5
             #RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True
         }catch{
            Write-Error "Applying the Wallpaper was unsuccessful."
         }
    }
}

function Alert-User ($Message = "Click OK to continue or CANCEL to exit script", $Title = "Continue or Cancel") {



    Add-Type -AssemblyName System.Windows.Forms | Out-Null

    $MsgBox = [System.Windows.Forms.MessageBox]



    $Decision = $MsgBox::Show($Message,$Title,"OkCancel", "Warning")

    If ($Decision -eq "Cancel") {exit}



}

function Assess-UserRansom {
    <#
        .SYNOPSIS

            Creates a GUI for the User to see that files are being "Encrypted" but in this tool, they are not being encrypted, but simulating encryption happening.

        .PARAMETER Paths

            Must be an array of Paths. By default, uses @("C:\Users\*\Documents","C:\Users\*\Dropbox","C:\Users\*\Desktop","C:\Users\*\OneDrive","C:\Users\*\Box Sync")

        .PARAMETER fileExtensions

            Must be an array of extensions. By default, it uses the following: @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")

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
        $fileExtensions = @("*.doc*","*.txt","*.xls*","*.png","*.jpg","*.jpeg","*.pdf","*.csv","*.tiff")
    )

    Add-Type -assembly System.Windows.Forms

    	## -- Create The Window
    	$ObjForm = New-Object System.Windows.Forms.Form
    	$ObjForm.Text = "Encrypting Files. . ."
    	$ObjForm.Height = 200
    	$ObjForm.Width = 500
    	$ObjForm.BackColor = "White"

        ## -- Create The information Window
    	$ObjForm1 = New-Object System.Windows.Forms.Form
    	$ObjForm1.Text = "Information to Recover Files"
    	$ObjForm1.Height = 200
    	$ObjForm1.Width = 500
    	$ObjForm1.BackColor = "White"
    	$ObjForm1.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
    	$ObjForm1.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    	$ObjForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
    	$ObjForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    	## -- Create The Labels
    	$ObjLabel = New-Object System.Windows.Forms.Label
    	$ObjLabel.Text = "Starting. Please wait ... "
    	$ObjLabel.Left = 5
    	$ObjLabel.Top = 10
    	$ObjLabel.Width = 500 - 20
    	$ObjLabel.Height = 15
    	$ObjLabel.Font = "Tahoma"
        $ObjLabel2 = New-Object System.Windows.Forms.Label
    	$ObjLabel2.Text = "Starting. Please wait ... "
    	$ObjLabel2.Left = 5
    	$ObjLabel2.Top = 80
    	$ObjLabel2.Width = 500 - 20
    	$ObjLabel2.Height = 15
    	$ObjLabel2.Font = "Tahoma"
    	## -- Add the label to the Form
    	$ObjForm.Controls.Add($ObjLabel)
        $ObjForm.Controls.Add($ObjLabel2)

    	$PB = New-Object System.Windows.Forms.ProgressBar
    	$PB.Name = "PowerShellProgressBar"
    	$PB.Value = 0
    	$PB.Style="Continuous"

    	$System_Drawing_Size = New-Object System.Drawing.Size
    	$System_Drawing_Size.Width = 500 - 40
    	$System_Drawing_Size.Height = 20
    	$PB.Size = $System_Drawing_Size
    	$PB.Left = 5
    	$PB.Top = 40
    	$ObjForm.Controls.Add($PB)

    	## -- Show the Progress-Bar and Start The PowerShell Script
    	$ObjForm.Show() | Out-Null
    	$ObjForm.Focus() | Out-NUll
    	$ObjLabel.Text = "Starting. Please wait ... "
    	$ObjForm.Refresh()


    	Start-Sleep -Seconds 1

    	## -- Execute The PowerShell Code and Update the Status of the Progress-Bar

    	$Result = Get-ChildItem -Path $Paths -Include $fileExtensions -Recurse -Force -ErrorAction SilentlyContinue | Select-Object Name, @{Name="Path";Expression={$_.FullName}}, @{n="SizeMB";e={[int]($_.length/1MB)}}
    	$Counter = 0
    	ForEach ($Item In $Result) {
    		## -- Calculate The Percentage Completed
    		$Counter++
    		[Int]$Percentage = ($Counter/$Result.Count)*100
    		$PB.Value = $Percentage
    		$ObjLabel.Text = "Encrypting Files for $env:Username"
            $ObjLabel2.Text = "Current file: " + $Item.Name
    		$ObjForm.Refresh()
		#Take the file size and use it to vary the length of time shown in the window
    		Start-Sleep -milliseconds ($Item.SizeMB * 10)
    		# -- $Item.Name
    		#Remove below comment for troubleshooting path in PS window
            #"`t" + $Item.Path

    	}

    	$ObjForm.Close()
    	Write-Host "`n"

        Alert-User -Message "$Counter files are now encrypted. Please contact IT for further instructions." -Title "Successfully Encrypted"

}
