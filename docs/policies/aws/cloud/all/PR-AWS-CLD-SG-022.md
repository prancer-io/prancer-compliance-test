



# Master Test ID: PR-AWS-CLD-SG-022


Master Snapshot Id: ['TEST_SG']

type: rego

rule: [file(securitygroup.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SG-022|
|eval: |data.rule.sg_tag|
|message: |data.rule.sg_tag_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-tags' target='_blank'>here</a>, provide security group tags|
|remediationFunction: |PR_AWS_CLD_SG_022.py|


severity: Medium

title: Ensure AWS resources that support tags have Tags

description: Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['security group']|



[file(securitygroup.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
