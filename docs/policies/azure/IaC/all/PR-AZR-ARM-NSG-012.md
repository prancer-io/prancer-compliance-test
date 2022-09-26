



# Title: RedisWannaMine vulnerable instances with active network traffic should be locked down


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NSG-012

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NSG-012|
|eval|data.rule.inbound_port_6379|
|message|data.rule.inbound_port_6379_err|
|remediationDescription|Make sure you are following the ARM template guidelines for NSG by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NSG_012.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** RedisWannaMine is cryptojacking attack which aims at both database servers and application servers via remote code execution, exploiting an Apache Struts vulnerability. To inject cryptocurrency mining malware, RedWannaMine uses a transmission control protocol (TCP) scanner to check open port 445 of SMB and scans vulnerable Redis server database over port 6379(tcp), so that it can use EternalBlue to spread further.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networksecuritygroups']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/nsg.rego
