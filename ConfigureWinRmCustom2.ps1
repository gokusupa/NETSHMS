#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(

   [Parameter(Mandatory = $true)]
 [string] $HostName
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    try
    {
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains("HTTPS"))
            {
                Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."
    
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
                break
            }
        }
    }
    catch
    {
        Write-Verbose -Verbose "Exception while deleting the listener: " + $_.Exception.Message
    }
}

function Create-Certificate
{
    param(
        [string]$hostname
    )

    # makecert ocassionally produces negative serial numbers
	# which golang tls/crypto <1.6.1 cannot handle
	# https://github.com/golang/go/issues/8265
    $cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $hostname 
    Write-Verbose $cert.Thumbprint -Verbose
    if(-not $cert.Thumbprint)
    {
        throw "Failed to create the test certificate."
    }

    #Verify Serial is valid
   $serial = Get-ChildItem -Path $cert.PSPath | select -ExpandProperty serialnumber
   $serialconvert = [System.Numerics.BigInteger]::Parse("$($serial)", 'AllowHexSpecifier')
   Write-Verbose "$serialconvert if first digit is 0-7 this is a positive, anything else is negative" -Verbose
   

    if ($serialconvert -match "^[0-7]" )
    {
        Write-Verbose "Positive" -Verbose
    }

    else
    {
        Write-Verbose "Negative" -Verbose
        Write-Verbose "Removing Negative cert and creating new one" -Verbose
        Get-childitem cert:\localmachine\my | ? {$_.Subject -like "CN=vmwork*"} | Remove-Item -Force -Confirm:$false
        Write-Verbose "Creating new cert" -Verbose
        $cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $hostname 
        Write-Verbose $cert.Thumbprint -Verbose
        if(-not $cert.Thumbprint)
        {
            throw "Failed to create the test certificate."
        }
        $thumbprint = $cert.Thumbprint
        return $thumbprint

    }

        $thumbprint = $cert.Thumbprint
    return $thumbprint


}

function Configure-WinRMHttpsListener
{
    param([string] $HostName,
          [string] $port)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    # Create a test certificate
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
	    $thumbprint = Create-Certificate -hostname $HostName
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped
        # Delete the certificate
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force
        $thumbprint = Create-Certificate -hostname $HostName
    }

    $WinrmCreate= "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$hostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    winrm set winrm/config/service/auth '@{Basic="true"}'
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
}


#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

$winrmHttpsPort=5986

# The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
# results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

# Configure https listener
Configure-WinRMHttpsListener $HostName $port 

# Add firewall exception
Add-FirewallException -port $winrmHttpsPort 

#################################################################################################################################
#################################################################################################################################