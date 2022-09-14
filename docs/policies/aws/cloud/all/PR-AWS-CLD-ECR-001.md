



# Master Test ID: PR-AWS-CLD-ECR-001


Master Snapshot Id: ['TEST_ECR']

type: rego

rule: [file(ecr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECR-001|
|eval: |data.rule.ecr_imagetag|
|message: |data.rule.ecr_imagetag_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECR_001.py|


severity: Medium

title: Ensure ECR image tags are immutable

description: Amazon ECR supports immutable tags, preventing image tags from being overwritten. In the past, ECR tags could have been overwritten, this could be overcome by requiring users to uniquely identify an image using a naming convention.Tag Immutability enables users can rely on the descriptive tags of an image as a mechanism to track and uniquely identify images. By setting an image tag as immutable, developers can use the tag to correlate the deployed image version with the build that produced the image.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecr']|



[file(ecr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
