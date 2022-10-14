



# Title: Ensure termination protection in stacks is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CFR-006

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_14']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-006|
|eval|data.rule.termination_protection_in_stacks_is_enabled|
|message|data.rule.termination_protection_in_stacks_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the stack is protected against accidental termination which may lead to deletion of critical resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
