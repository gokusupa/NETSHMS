$password =  ConvertTo-SecureString "template!PWD" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\caadmin", $password)
$command = $file = $PSScriptRoot + "\NETSH2.ps1"
Enable-PSRemoting –force
Invoke-Command -FilePath $command -Credential $credential -ComputerName $env:COMPUTERNAME
