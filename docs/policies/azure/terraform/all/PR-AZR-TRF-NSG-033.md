



# Master Test ID: PR-AZR-TRF-NSG-033


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-033|
|eval: |data.rule.inbound_port_137|
|message: |data.rule.inbound_port_137_err|
|remediationDescription: |In 'azurerm_network_security_rule' resource, make sure property 'destination_port_range' dont have port '137' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#destination_port_range' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_NSG_033.py|


severity: Medium

title: Azure Network Security Group should not allow NetBIOS (UDP Port 137)

description: This policy detects any NSG rule that allows NetBIOS traffic on UDP port 137 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict NetBIOS solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
