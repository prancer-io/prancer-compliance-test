



# Title: Azure Network Security Group (NSG) having Inbound rule overly permissive to all UDP traffic from any source


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-NSG-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-002|
|eval|data.rule.nsg_in_udp_all_src|
|message|data.rule.nsg_in_udp_all_src_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_NSG_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to open UDP traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
