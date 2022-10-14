



# Title: Internet connectivity via tcp over insecure port should be prevented


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NSG-010

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NSG-010|
|eval|data.rule.inbound_insecure_port|
|message|data.rule.inbound_insecure_port_err|
|remediationDescription|Make sure you are following the ARM template guidelines for NSG by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NSG_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'HIPAA', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networksecuritygroups']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/nsg.rego
