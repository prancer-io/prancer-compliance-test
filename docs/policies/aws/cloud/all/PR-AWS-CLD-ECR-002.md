



# Master Test ID: PR-AWS-CLD-ECR-002


Master Snapshot Id: ['TEST_ECR']

type: rego

rule: [file(ecr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECR-002|
|eval: |data.rule.ecr_encryption|
|message: |data.rule.ecr_encryption_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECR_002.py|


severity: High

title: Ensure ECR repositories are encrypted

description: Make sure EncryptionType is present in ECR EncryptionConfiguration To increase control of the encryption and control the management of factors like key rotation  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecr']|



[file(ecr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
