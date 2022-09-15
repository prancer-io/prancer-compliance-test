



# Master Test ID: PR-AWS-CLD-ECR-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECR-005|
|eval|data.rule.ecr_vulnerability|
|message|data.rule.ecr_vulnerability_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECR_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Enable Enhanced scan type for AWS ECR registry to detect vulnerability

***<font color="white">Description:</font>*** Enable Enhanced scan type for AWS ECR registry to detect vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR']|
|service|['ecr']|



[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
