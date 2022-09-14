



# Master Test ID: PR-AZR-TRF-SEC-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: python

rule: [file(secret_tf.py)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SEC-002|
|eval: |password_leak|
|message: |password_leak_err|
|remediationDescription: ||
|remediationFunction: |PR_AZR_TRF_SEC_002.py|


severity: High

title: There is a possibility that secure password is exposed

description: There is a possibility that secure password is exposed. Make sure to put those secrets in a vault and access from there.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|



[file(secret_tf.py)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/secret_tf.py
