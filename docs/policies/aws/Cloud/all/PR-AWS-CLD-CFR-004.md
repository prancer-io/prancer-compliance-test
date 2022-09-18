



# Title: Ensure an IAM policy is defined with the stack.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CFR-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_14']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-004|
|eval|data.rule.role_arn_exist|
|message|data.rule.role_arn_exist_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Stack policy protects resources from accidental updates, the policy included resources which shouldn't be updated during the template provisioning process.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
