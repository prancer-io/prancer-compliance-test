



# Master Test ID: PR-AZR-TRF-SEC-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(secrets.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SEC-001|
|eval: |data.rule.gl_azure_secrets|
|message: |data.rule.gl_azure_secrets_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_SEC_001.py|


severity: Medium

title: Ensure Secrets are not hardcoded in the template

description: Secrets should not be hardcoded in the Template. Make sure to put those secrets in a vault and access from there.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|



[file(secrets.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/secrets.rego
