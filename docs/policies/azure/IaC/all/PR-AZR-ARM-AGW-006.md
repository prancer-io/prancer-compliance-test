



# Title: Ensure Application Gateway secret certificates stores in keyvault


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AGW-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AGW-006|
|eval|data.rule.secret_certificate_is_in_keyvalut|
|message|data.rule.secret_certificate_is_in_keyvalut_err|
|remediationDescription|For resource type 'microsoft.network/applicationgateways' make sure 'properties.keyVaultSecretId' has target key vault id under 'sslCertificates' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways?tabs=json#applicationgatewaysslcertificate' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AGW_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/applicationgateways']


[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego
