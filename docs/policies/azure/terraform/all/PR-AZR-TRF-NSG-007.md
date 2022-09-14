



# Master Test ID: PR-AZR-TRF-NSG-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(nsg.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-NSG-007|
|eval: |data.rule.nsg_in_all_dst|
|message: |data.rule.nsg_in_all_dst_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_NSG_007.py|


severity: High

title: Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source to any destination

description: This policy identifies NSGs which allows incoming traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources on authorized protocols and ports.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_network_security_rule']


[file(nsg.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
