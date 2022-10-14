



# Title: Azure Network Security Group (NSG) has an Inbound rule overly permissive to allow all traffic from any source to any destination


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-NSG-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_231']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-NSG-007|
|eval|data.rule.nsg_in_all_dst|
|message|data.rule.nsg_in_all_dst_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/security/fundamentals/network-overview' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_NSG_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies NSGs which allows incoming traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources on authorized protocols and ports.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Networking']|



[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/nsg.rego
