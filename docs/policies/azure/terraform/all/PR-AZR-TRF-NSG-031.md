



# Title: Instance is communicating with ports known to mine Bitcoin


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-NSG-031

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-NSG-031|
|eval|data.rule.outbound_port_bitcoin|
|message|data.rule.outbound_port_bitcoin_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_NSG_031.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_network_security_rule']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/nsg.rego
