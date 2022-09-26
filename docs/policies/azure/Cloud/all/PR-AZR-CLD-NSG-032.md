



# Title: Instance should not be allowed communicating with ports known to mine Ethereum


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-NSG-032

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_231']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([nsg.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-NSG-032|
|eval|data.rule.outbound_port_ethereum|
|message|data.rule.outbound_port_ethereum_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/security/fundamentals/network-overview' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_NSG_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['HIPAA', 'NIST CSF']|
|service|['Networking']|



[nsg.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/nsg.rego
