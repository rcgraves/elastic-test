#######################
# CAMTableExport.ps1
#
# Version:      1.0
# Author:       Justin Henderson
# Requirements: Posh-SSH module installed (https://github.com/darkoperator/Posh-SSH)
#
# Description: This script is used to connect to switches and export their CAM table.
# It is useful for identifying devices plugged into a network.

Import-Module Posh-SSH
# Modify this array with a list of your switches
$switches = @("10.0.0.240")
# Current supported output limited to csv
$destination = "csv"
# If enable password is not required then set to $enable_password = ""
$enable_password = "password"
# Set $force = 1 if you want to force remove error and output files at run time
# This is only necessary if output is in a folder with other files that may not
# be generated from this script.
$force = 0

# BEGIN SCRIPT - Do not edit pass this line unless you are comfortable with scripting
if(Get-ChildItem | Where-Object { $_.Name -notmatch "output_*.txt" -and $_.Name -ne "error.txt"}){
    $userInput = Read-Host -Prompt "Files found that do not match output files generated from this script. Continue? (y/n)"
    if($userInput -ne "y" -or $userInput -ne "Y"){
        Exit
    }
}

Remove-Item "error.txt" -ErrorAction SilentlyContinue
Remove-Item "output_*.txt" -ErrorAction SilentlyContinue

foreach($switch in $switches){
    Get-SSHSession | Remove-SSHSession | Out-Null
    $username = "admin"
    $password = "password"
    $credpassword = $password | ConvertTo-SecureString -asPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential ($username, $credpassword)
    $connect = 0
    try {
        new-object System.Net.Sockets.TcpClient($switch, "22") | Out-Null
        $connect = 1
    }
    catch {
        $connect = 0
    }
    if($connect -eq 1){
        Write-Host "Port 22 is open on $switch" -ForegroundColor Green
        if($session = New-SSHSession -AcceptKey:$true -ComputerName $switch -Credential $credentials -ConnectionTimeout 10){
            Write-Host "SSH session established to $switch" -ForegroundColor Green
            $stream = New-SSHShellStream -SSHSession $session
            if($enable_password -ne ""){
                Invoke-SSHStreamExpectAction -ShellStream $stream -Command "enable" -ExpectString "Password:" -Action "$enable_password`n" | Out-Null
            } else {
                Invoke-SSHStreamExpectAction -ShellStream $stream -Command "enable" -ExpectString "#" -Action "password`n" | Out-Null
            }
            Invoke-SSHStreamExpectAction -ShellStream $stream -Command "terminal length 0" -ExpectString "#" -Action "`n" | Out-Null
            if(Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show version" -ExpectString "cisco" -Action "`n"){
                    $type = "cisco"
                }
            Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show mac address-table" -ExpectString "Mac Address Table" -Action "`n" | Out-Null
            $output = ""
            Do {
                $output += $stream.Read()
                if($count -ge 1){
                    Sleep -Seconds 5
                }
                $count++
            }
            while($output -notmatch "Total Mac Address" -or $count -eq 5)
            $lines = $output -split "\n"
            $entries = @()
            foreach($line in $lines){
                if($line -match "....\.....\....." -and $line -notmatch "CPU"){
                    if($type -eq "cisco"){
                        # first column is vlan - parse with below
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $vlan = $split[0]
                        $vlanLength = $vlan.Length
                        # second column is mac address - parse with below
                        $line = $line.Substring($vlanLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $mac = $split[0]
                        $macLength = $mac.Length
                        $mac = $mac -replace '\.',''
                        $mac = $mac.Substring(0,2) + ":" + $mac.Substring(2,2) + ":" + $mac.Substring(4,2) + ":" + $mac.Substring(6,2) + ":" + $mac.Substring(8,2) + ":" + $mac.Substring(10,2)
                        # third column is mac learning type - parse with below
                        $line = $line.Substring($macLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $macLearningType = $split[0].ToLower()
                        $macLearningTypeLength = $macLearningType.Length
                        # fourth column is interface type and port
                        $line = $line.Substring($macLearningTypeLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $port = $split[0].ToLower()
                        if($port -match "^gi"){
                            $port_type = "gigabit"
                        }
                        if($port -match "^po"){
                            $port_type = "port channel"
                        }
                        $unit = $port -split "\/"
                        $unit = $unit[0] -replace '\D+(\d+)','$1'
                        $entry = New-Object -TypeName PSObject
                        $entry | Add-Member -Name "mac" -MemberType NoteProperty -Value $mac
                        $entry | Add-Member -Name "port" -MemberType NoteProperty -Value $port
                        $entry | Add-Member -Name "port_type" -MemberType NoteProperty -Value $port_type
                        $entry | Add-Member -Name "switch" -MemberType NoteProperty -Value $switch
                        $entry | Add-Member -Name "switchType" -MemberType NoteProperty -Value $type
                        $entry | Add-Member -Name "vlan" -MemberType NoteProperty -Value $vlan
                        $entry | Add-Member -Name "unit" -MemberType NoteProperty -Value $unit
                        $entries += $entry
                    }
                }
            }
            if($destination -eq "csv"){
                $entries | Export-Csv -Path "output_$switch.txt" -Force -NoTypeInformation
            }
            Get-SSHSession | Remove-SSHSession | Out-Null
        } else {
            Write-Host "Unable to connect to $switch" -ForegroundColor Red
            Write-Output "Unable to connect to $switch" | Out-File error.txt -Append -Force
        }
    } else {
        Write-Host "Port 22 is not open on $switch" -ForegroundColor Red
        Write-Output "Port 22 is not open on $switch" | Out-File error.txt -Append -Force
    }
}