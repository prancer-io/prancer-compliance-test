



# Master Test ID: PR-AZR-TRF-SEC-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([secrets.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SEC-001|
|eval|data.rule.gl_azure_secrets|
|message|data.rule.gl_azure_secrets_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_SEC_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Secrets are not hardcoded in the template

***<font color="white">Description:</font>*** Secrets should not be hardcoded in the Template. Make sure to put those secrets in a vault and access from there.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|



[secrets.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/secrets.rego
