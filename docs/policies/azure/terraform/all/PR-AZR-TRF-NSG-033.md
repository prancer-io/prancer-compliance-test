



# Title: Azure Network Security Group should not allow NetBIOS (UDP Port 137)


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-NSG-033

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-033|
|eval|data.rule.inbound_port_137|
|message|data.rule.inbound_port_137_err|
|remediationDescription|In 'azurerm_network_security_rule' resource, make sure property 'destination_port_range' dont have port '137' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#destination_port_range' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_NSG_033.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy detects any NSG rule that allows NetBIOS traffic on UDP port 137 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict NetBIOS solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
