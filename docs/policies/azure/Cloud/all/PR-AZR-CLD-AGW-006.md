



# Title: Ensure Application Gateway secret certificates stores in keyvault


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AGW-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_221']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AGW-006|
|eval|data.rule.secret_certificate_is_in_keyvalut|
|message|data.rule.secret_certificate_is_in_keyvalut_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/application-gateway/key-vault-certs' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AGW_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Networking']|



[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/applicationgateways.rego
