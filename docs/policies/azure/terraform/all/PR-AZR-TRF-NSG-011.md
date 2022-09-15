



# Master Test ID: PR-AZR-TRF-NSG-011


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-011|
|eval|data.rule.inbound_port_11211|
|message|data.rule.inbound_port_11211_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_NSG_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Memcached DDoS attack attempt should be prevented

***<font color="white">Description:</font>*** Memcached is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read. It is reported that Memcache versions 1.5.5 and below are vulnerable to DDoS amplification attack. This policy aims at finding such attacks and generate alerts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
