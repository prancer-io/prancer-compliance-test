



# Master Test ID: PR-AZR-TRF-NSG-012


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-012|
|eval|data.rule.inbound_port_6379|
|message|data.rule.inbound_port_6379_err|
|remediationDescription|In 'azurerm_network_security_rule' resource, make sure property 'destination_port_range' dont have port '6379' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#destination_port_range' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_NSG_012.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** RedisWannaMine vulnerable instances should not allow network traffic on port 6379

***<font color="white">Description:</font>*** RedisWannaMine is cryptojacking attack which aims at both database servers and application servers via remote code execution, exploiting an Apache Struts vulnerability. To inject cryptocurrency mining malware, RedWannaMine uses a transmission control protocol (TCP) scanner to check open port 445 of SMB and scans vulnerable Redis server database over port 6379(tcp), so that it can use EternalBlue to spread further.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
