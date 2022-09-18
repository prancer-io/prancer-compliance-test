



# Title: Internet connectivity via tcp over insecure port should be prevented


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-NSG-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-010|
|eval|data.rule.inbound_insecure_port|
|message|data.rule.inbound_insecure_port_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_NSG_010.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'HIPAA', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
