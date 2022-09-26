



# Title: Ensure no hardcoded password set in the template


***<font color="white">Master Test Id:</font>*** PR-AWS-0031-RGX

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_tf.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0031-RGX|
|eval|password_leak|
|message|password_leak_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure no hardcoded password set in the template, template should not have any secret in it. Make sure to put the secrets in a vault  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** []


[secret_tf.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/secret_tf.py
