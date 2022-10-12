  <#
      .SYNOPSIS
        Adds rules to an existing NSG

      .DESCRIPTION
        Script to update a NSG with a set of rules. 
        
        2 sets of rules can be specified: a set of ""default" rules which might be applicable to more than 1 NSG and a set of
        NSG-specific rules (both are optional)

        The use case behind the script is that NSG rules can be defined in JSON and used in several places (ARM or Bicep templates or this script)

      .PARAMETER NSGName
		Name of the Network Security Group (required)
      
	  .PARAMETER specificNSGRules
		Full path to the JSON file containing NSG-specific rules.

	  .PARAMETER defaultRulesJson
		Full path to the JSON file containing default rules (such as allowing AllowAzureLoadBalancerInBound or denying intra-VNet traffic).

      .PARAMETER Simulate
		if the -Simulate paramter is set the scripts runs but does not actually update the NSG. Can be used to validate JSON files.

      .EXAMPLE
        .\Add-NSGRules.ps1 -NSGName MyNSG -specificNSGRules c:\temp\MyNSG.json -defaultRulesJson c:\temp\defaultRules.json -Simulate

      .PREREQUISITES
        Requires Powershell 7.x and the Az.Account and Az.Network modules

      .NOTES
	  	Author: 	S. Jambor / RapidCircle
		Version:	1.0
		Released:	2022 10 12
     
	  .TODO
	    - Include a mechanism for dealing removing rules not defined in the JSON

	  
  #>
Param(
	[Parameter (Mandatory= $true)]
 	[string]$NSGName,

	[Parameter (Mandatory= $false)]
 	[string]$specificNSGRules = "C:\temp\specificNSGRules.json",

	[Parameter (Mandatory= $false)]
 	[string]$defaultRulesJson = "C:\temp\defaultRules.json", 

	[Parameter (Mandatory= $false)]
 	[switch]$Simulate
)

Begin {
    #Do we need to log into Azure?
    if ([string]::IsNullOrEmpty($(Get-AzContext).Account)) {Connect-AzAccount}

    #Can we reach the NSG? Exit if not.
    try {
        $nsg = Get-AzNetworkSecurityGroup -Name $NSGName

    } 
    catch {
        write-Warning -Message "There is no such NSG. Exiting."
        Exit
    }

    #Import the rules from JSON files; exit if we don't have rules
    $rules = @()
    if($specificNSGRules -ne '') {
        if(Test-Path -Path $specificNSGRules) {
            $rules +=  Get-Content $specificNSGRules | ConvertFrom-Json -AsHashtable
        } else {Write-Error -Message "JSON input file $specificNSGRules not found"}
    }

    if($defaultRulesJson -ne '') {
        if(Test-Path -Path $defaultRulesJson) {
            $rules +=  Get-Content $defaultRulesJson | ConvertFrom-Json -AsHashtable
        } else {Write-Error -Message "JSON input file $defaultRulesJson not found"}
    }

    if($rules.Count -eq 0) {
        Write-Warning -Message "No rules have been defined, so nothing to do. Exiting without doing anything."
        Exit
    }

}

Process {
    foreach($rule in $rules){
        #A rule with the same Priority or Name should not exist already
        if( `
            $($nsg.SecurityRules | Where-Object {$_.Name -eq $rule.Name}).Count -eq 0 -and `
            $($nsg.SecurityRules | Where-Object {$_.Priority -eq $rule.Priority}).Count -eq 0 `
            ) {

            if($rule.SourceApplicationSecurityGroupNames -ne $null){
                foreach($SourceApplicationSecurityGroupName in $rule.SourceApplicationSecurityGroupNames){
                    try{
                    # $SourceApplicationSecurityGroupName="JMB-ASG-AVDFinanceHosts"
                        $destASG = Get-AzApplicationSecurityGroup -Name $SourceApplicationSecurityGroupName
                        } 
                    catch {
                        Write-Error -Message "No such ASG: $SourceApplicationSecurityGroupName"
                        break
                        }
                    if($rule.SourceApplicationSecurityGroup -eq $null){
                        $rule.Add("SourceApplicationSecurityGroup",@($destASG))
                    } else {
                        $rule.SourceApplicationSecurityGroup += $destASG
                    }
                }
                $rule.Remove("SourceApplicationSecurityGroupNames")
            }

        "doing things for " + $rule.name
        $nsg | Add-AzNetworkSecurityRuleConfig @rule -Direction Inbound
        } else {"already have a rule $($rule.name) (with priority $($rule.Priority))"}
    }
    if(!($Simulate)) {
        $nsg | Set-AzNetworkSecurityGroup
    }
}