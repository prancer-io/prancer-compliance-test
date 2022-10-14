



# Title: Ensure Application Gateway Backend is using Https protocol


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AGW-005

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_221']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AGW-005|
|eval|data.rule.backend_https_protocol_enabled|
|message|data.rule.backend_https_protocol_enabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/application-gateway/end-to-end-ssl-portal' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AGW_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Networking']|



[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/applicationgateways.rego
