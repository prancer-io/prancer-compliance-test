



# Master Test ID: PR-AWS-CLD-ECR-005


Master Snapshot Id: ['TEST_ECR']

type: rego

rule: [file(ecr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECR-005|
|eval: |data.rule.ecr_vulnerability|
|message: |data.rule.ecr_vulnerability_err|
|remediationDescription: |Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECR_005.py|


severity: High

title: Enable Enhanced scan type for AWS ECR registry to detect vulnerability

description: Enable Enhanced scan type for AWS ECR registry to detect vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'GDPR']|
|service: |['ecr']|



[file(ecr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
