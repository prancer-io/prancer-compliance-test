



# Title: Instance should not be allowed communicating with ports known to mine Ethereum


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NSG-032

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NSG-032|
|eval|data.rule.outbound_port_ethereum|
|message|data.rule.outbound_port_ethereum_err|
|remediationDescription|Make sure you are following the ARM template guidelines for NSG by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NSG_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'NIST CSF']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/networksecuritygroups']


[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/nsg.rego
