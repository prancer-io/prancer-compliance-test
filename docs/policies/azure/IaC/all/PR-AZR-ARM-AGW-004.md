



# Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AGW-004

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AGW-004|
|eval|data.rule.frontendPublicIPConfigurationsDisabled|
|message|data.rule.frontendPublicIPConfigurationsDisabled_err|
|remediationDescription|For resource type 'microsoft.network/applicationgateways' make sure 'properties.publicIPAddress' does not exist under 'frontendIPConfigurations' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways?tabs=json#applicationgatewayfrontendipconfiguration' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AGW_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/applicationgateways']


[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego
