



# Title: Ensure lifecycle policy is enabled for ECR image repositories.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-007|
|eval|data.rule.lifecycle_policy_is_enabled|
|message|data.rule.lifecycle_policy_is_enabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_lifecycle_policy']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
