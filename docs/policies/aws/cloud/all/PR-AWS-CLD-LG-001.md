



# Master Test ID: PR-AWS-CLD-LG-001


Master Snapshot Id: ['TEST_ALL_03']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-LG-001|
|eval: |data.rule.log_group_encryption|
|message: |data.rule.log_group_encryption_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_LG_001.py|


severity: High

title: Ensure CloudWatch log groups are encrypted with KMS CMKs

description: CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['cloudwatch']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
