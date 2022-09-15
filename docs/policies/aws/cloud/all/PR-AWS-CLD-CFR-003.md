



# Master Test ID: PR-AWS-CLD-CFR-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_14']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-003|
|eval|data.rule.cloudFormation_rollback_is_disabled|
|message|data.rule.cloudFormation_rollback_is_disabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure Cloudformation rollback is disabled.

***<font color="white">Description:</font>*** It checks the stack rollback setting, in case of a failure do not rollback the entire stack. We can use change sets run the stack again, after fixing the template. Resources which are already provisioned won't be re-created.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
