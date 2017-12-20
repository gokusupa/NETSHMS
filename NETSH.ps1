$pw = ConvertTo-SecureString template!PWD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('CAAdmin', $pw)
$session = New-PSSession  -Credential $cred
Invoke-Command -Session $session -ScriptBlock {Netsh trace start scenario=netconnection capture=yes report=yes persistent=yes maxsize=4096 tracefile=c:\trace.etly}

