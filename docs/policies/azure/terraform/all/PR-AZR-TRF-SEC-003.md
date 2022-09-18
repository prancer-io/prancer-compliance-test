



# Title: There is a possibility that secure password is exposed


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SEC-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_tf.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SEC-003|
|eval|entropy_password|
|message|entropy_password_err|
|remediationDescription||
|remediationFunction|PR_AZR_TRF_SEC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** There is a possibility that secure password is exposed. Make sure to put those secrets in a vault and access from there.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|



[secret_tf.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/secret_tf.py
