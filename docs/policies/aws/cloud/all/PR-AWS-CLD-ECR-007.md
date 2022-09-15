



# Master Test ID: PR-AWS-CLD-ECR-007


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECR-007|
|eval|data.rule.lifecycle_policy_is_enabled|
|message|data.rule.lifecycle_policy_is_enabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.get_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECR_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure lifecycle policy is enabled for ECR image repositories.

***<font color="white">Description:</font>*** It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR']|
|service|['ecr']|



[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
