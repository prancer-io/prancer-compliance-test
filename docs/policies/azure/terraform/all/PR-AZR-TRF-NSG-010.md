



# Master Test ID: PR-AZR-TRF-NSG-010


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-010|
|eval: |data.rule.inbound_insecure_port|
|message: |data.rule.inbound_insecure_port_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_NSG_010.py|


severity: High

title: Internet connectivity via tcp over insecure port should be prevented

description: Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['GDPR', 'HIPAA', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
