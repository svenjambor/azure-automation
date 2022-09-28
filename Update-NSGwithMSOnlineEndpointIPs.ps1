  <#
      .SYNOPSIS
      Updates specific NSG rule with MS365 endpoints

      .DESCRIPTION
		Retrieves Microsoft Office 365 endpoints for a specific set of service and port. The runbok compares this information to 
		the content of an NSG rule and updates it as required.

      .PARAMETER NSGName
		Name of the Network Security Group (required)
      
	  .PARAMETER NSGRuleName
		Name of the rule within the NSG (required)

	  .PARAMETER IPVersion
		IP version: specify 4 or 6; if neither is specified then 4 is assumed

      .PARAMETER ServiceArea
		Each O365 service has an "servicearea" name in the REST results (e.g. "Exchange" for Exchange Online) (required)

      .EXAMPLE
        Intende to run as runbook from a schedule or a webhook using the parameters to re-use it for all kinds of scenarios

      .PREREQUISITES
        Requires Az.Account and Az.Network modules

      .NOTES
	  	Author: 	S. Jambor / RapidCircle
		Version:	1.0
		Released:	2022 09 28
     
	  .TODO
	    - Include a mechanism for dealing with required vs optional/optimize ip addresses

	  
  #>

Param(
	[Parameter (Mandatory= $true)]
 	[string]$NSGName,

	[Parameter (Mandatory= $true)]
 	[string]$NSGRuleName,

	[Parameter (Mandatory= $false)]
 	[string]$IPVersion = "4", 

	[Parameter (Mandatory= $true)]
 	[string]$ServiceArea
)

Begin {

# LOGIN using Identity
	# Ensures you do not inherit an AzContext in your Runbook
	Disable-AzContextAutosave -Scope Process | Out-Null

	# Connect using a Managed Service Identity
	try {
			$AzureContext = (Connect-AzAccount -Identity).context
		}
	catch {
			Write-Output "There is no system-assigned user identity. Aborting."; 
			exit
		}

# Retrieve MSO365 IP Addresses
	try {
		$o365IpList = Invoke-Restmethod "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((new-guid).guid)"
	}
	catch {
		write-output "Could not retrieve O365 IP List"
		exit
	}

# Get the NSG and set variables based on it
	try {
		$objNSG = $(Get-AzNetworkSecurityGroup -Name $NSGName)[0]

	} 
	catch {
		write-output message "No such NSG"
		exit
	}

	try {
		$objNSGRule = $($objNSG.SecurityRules | Where-Object {$_.Name -eq $NSGRuleName})[0]
	}
	catch {
		write-output "No such NSG rule"
		exit
	}
}

Process{

	#===== Get relevant IP addresses from REST call and put them in $servicePortIPs ===== 
	$servicePortIPs = New-Object System.Collections.ArrayList 

	# A NSG rule may contain more than 1 port. Search teh REST results for all entries of the ServiceArea containing these ports
	foreach($port in $objNSGRule.DestinationPortRange){
		$ipSet = ($o365IpList | where-object {$_.tcpPorts -like $("*" + $port + "*") -and $_.serviceArea -eq $ServiceArea}).ips
        foreach($line in $ipSet){
            $null = $servicePortIPs.Add($line)
        }
	}

	# We only want either IPv4 or IPv6 addresses since a rule cannot contain both.
	if($IPVersion -eq "6"){
		#IPv6 addresses contain :
		$ipAddressLike = "*:*"
		} 
	else {
		# If the IP version was not 6 we assume it's 4. IP4 addresses contain dots.
		$ipAddressLike = "*.*"
	}

	$servicePortIPs = $servicePortIPs | Where-Object {$_ -like $ipAddressLike} | Sort-Object -Unique

	#=== check difference beteen NSG en REST query result IP addresses ===

	#check if ip address have to be added to rule (ip address is in NSG rule but not in REST query result)
	# variable to determine if we have to update the NSG rule (possibly triggering alerts) or just end the run with nothing to do
	$bnRuleUpdateRequired = $false
	$NSGIPs = $objNSGRule.SourceAddressPrefix

	$servicePortIPs | ForEach-Object {
		if($NSGIPs -notcontains $_){
			write-output "Need to add $_ to rule"
			$null = $NSGIPs.add($_)
			$bnRuleUpdateRequired = $true
		}
	}

	#check if ip address have to be removed from rule (ip address is in REST query result but not in NSG rule )

	$removeRuleIPs = New-Object System.Collections.ArrayList 
	$NSGIPs | ForEach-Object {
		if($servicePortIPs -notcontains $_){
			$null = $removeRuleIPs.Add($_)
		}
	}

	if($removeRuleIPs.count -gt 0) {
		$removeRuleIPs | ForEach-Object {
			write-output "Removing $_ from rule"
			$null = $NSGIPs.Remove($_)
		}
		$bnRuleUpdateRequired = $true
	}

	# Update NSG with rule (if changes have to be made)
	if($bnRuleUpdateRequired){
		$($objNSG.SecurityRules | Where-Object {$_.Name -eq $NSGRuleName}).SourceAddressPrefix = $NSGIPs
		$objNSG | Set-AzNetworkSecurityGroup | Get-AzNetworkSecurityRuleConfig -Name $NSGRuleName
		Write-Output "Rule $NSGRuleName updated!"
	} else {Write-Output "Nothing to do... exiting"}
}
