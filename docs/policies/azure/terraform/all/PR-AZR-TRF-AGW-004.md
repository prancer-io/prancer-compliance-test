



# Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-AGW-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AGW-004|
|eval|data.rule.frontendPublicIPConfigurationsDisabled|
|message|data.rule.frontendPublicIPConfigurationsDisabled_err|
|remediationDescription|For resource type 'azurerm_application_gateway' make sure 'public_ip_address_id' does not exist under 'frontend_ip_configuration' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#frontend_ip_configuration' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AGW_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_application_gateway']


[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego
