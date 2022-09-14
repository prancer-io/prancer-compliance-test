



# Master Test ID: PR-AZR-TRF-NSG-017


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-017|
|eval: |data.rule.inbound_insecure_omi_port|
|message: |data.rule.inbound_insecure_omi_port_err|
|remediationDescription: |In 'azurerm_network_security_rule' resource, make sure property 'destination_port_range' dont have port '5985', '5986' and '1270' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#destination_port_range' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_NSG_017.py|


severity: High

title: Azure Network Security Group (NSG) should protect OMIGOD attack from internet

description: Blocking OMI port 5985, 5986, 1270 will protect vnet/subnet/vms from OMIGOD attacks from internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
