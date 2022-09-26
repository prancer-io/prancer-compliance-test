



# Title: Ensure lifecycle policy is enabled for ECR image repositories.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECR-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECR-007|
|eval|data.rule.lifecycle_policy_is_enabled|
|message|data.rule.lifecycle_policy_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECR_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecr::repository']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecr.rego
