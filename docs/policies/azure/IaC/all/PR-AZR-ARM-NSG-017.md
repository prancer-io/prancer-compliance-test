



# Title: Azure Network Security Group (NSG) should protect OMIGOD attack from internet


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NSG-017

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NSG-017|
|eval|data.rule.inbound_omi_port_blocked|
|message|data.rule.inbound_omi_port_blocked_err|
|remediationDescription|Make sure you are following the ARM template guidelines for NSG by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NSG_017.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Blocking OMI port 5985, 5986, 1270 will protect vnet/subnet/vms from OMIGOD attacks from internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networksecuritygroups']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/nsg.rego
