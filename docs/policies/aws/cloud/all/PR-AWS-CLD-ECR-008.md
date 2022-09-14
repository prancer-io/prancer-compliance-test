



# Master Test ID: PR-AWS-CLD-ECR-008


Master Snapshot Id: ['TEST_ECR', 'TEST_KMS']

type: rego

rule: [file(ecr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECR-008|
|eval: |data.rule.ecr_encrypted_using_key|
|message: |data.rule.ecr_encrypted_using_key_err|
|remediationDescription: |Make sure you are following the Terraform template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.describe_repositories' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECR_008.py|


severity: Medium

title: Ensure ECR is encrypted using dedicated GS managed KMS key.

description: It checks if a GS managed KMS key (CMK) is used for ECR encryption instead of AWS provided keys.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecr', 'kms']|



[file(ecr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
