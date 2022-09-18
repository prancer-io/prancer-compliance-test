



# Title: Ensure ECR repositories are encrypted


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-002|
|eval|data.rule.ecr_encryption|
|message|data.rule.ecr_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Make sure encryption_type is present in ECR encryption_configuration To increase control of the encryption and control the management of factors like key rotation  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_repository']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
