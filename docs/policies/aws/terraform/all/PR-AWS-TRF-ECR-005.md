



# Title: Enable Enhanced scan type for AWS ECR registry to detect vulnerability


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-005|
|eval|data.rule.ecr_vulnerability|
|message|data.rule.ecr_vulnerability_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable Enhanced scan type for AWS ECR registry to detect vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_registry_scanning_configuration']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
