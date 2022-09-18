



# Title: Ensure no hardcoded password set in the template


***<font color="white">Master Test Id:</font>*** PR-AWS-0031-RGX

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_aws_iac.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0031-RGX|
|eval|aws_password_leak|
|message|aws_password_leak_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure no hardcoded password set in the template, template should not have any secret in it. Make sure to put the secrets in a vault  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** []


[secret_aws_iac.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py
