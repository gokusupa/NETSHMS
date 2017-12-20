$pw = ConvertTo-SecureString "template!PWD" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\caadmin", $pw)
Enable-PSRemoting –force
$session = New-PSSession  -Credential $cred
Invoke-Command -Session $session -ScriptBlock {Netsh trace start scenario=netconnection capture=yes report=yes persistent=yes maxsize=4096 tracefile=c:\trace.etly}



