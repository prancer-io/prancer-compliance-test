



# Title: There is a possibility that secure password is exposed


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SEC-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_azure_iac.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SEC-002|
|eval|azure_password_leak|
|message|azure_password_leak_err|
|remediationDescription||
|remediationFunction|PR_AZR_ARM_SEC_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** There is a possibility that secure password is exposed. Make sure to put those secrets in a vault and access from there.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|



[secret_azure_iac.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/secret_azure_iac.py
