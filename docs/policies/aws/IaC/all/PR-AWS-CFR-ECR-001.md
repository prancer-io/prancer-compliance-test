



# Title: Ensure ECR image tags are immutable


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECR-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECR-001|
|eval|data.rule.ecr_imagetag|
|message|data.rule.ecr_imagetag_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECR_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Amazon ECR supports immutable tags, preventing image tags from being overwritten. In the past, ECR tags could have been overwritten, this could be overcome by requiring users to uniquely identify an image using a naming convention.Tag Immutability enables users can rely on the descriptive tags of an image as a mechanism to track and uniquely identify images. By setting an image tag as immutable, developers can use the tag to correlate the deployed image version with the build that produced the image.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecr::repository']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecr.rego
