



# Title: Ensure CloudFormation template is configured with stack policy.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CFR-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_16']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-002|
|eval|data.rule.cloudFormation_template_configured_with_stack_policy|
|message|data.rule.cloudFormation_template_configured_with_stack_policy_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.get_stack_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** In AWS IAM policy governs how much access/permission the stack has and if no policy is provided it assumes the permissions of the user running it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
