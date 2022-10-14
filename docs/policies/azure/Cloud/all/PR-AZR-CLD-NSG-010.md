



# Title: Internet connectivity via tcp over insecure port should be prevented


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-NSG-010

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_231']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-NSG-010|
|eval|data.rule.inbound_insecure_port|
|message|data.rule.inbound_insecure_port_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/security/fundamentals/network-overview' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_NSG_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['GDPR', 'HIPAA', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['Networking']|



[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/nsg.rego
