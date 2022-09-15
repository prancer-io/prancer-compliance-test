



# Master Test ID: PR-AWS-CLD-CFR-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_14']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-005|
|eval|data.rule.stack_with_not_all_capabilities|
|message|data.rule.stack_with_not_all_capabilities_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure capabilities in stacks do not have * in it.

***<font color="white">Description:</font>*** A CloudFormation stack needs certain capability, It is recommended to configure the stack with capabilities not all capabilities (*) should be configured. This will give the stack unlimited access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
