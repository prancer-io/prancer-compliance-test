



# Title: Ensure AWS ECR Repository is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-004|
|eval|data.rule.ecr_public_access_disable|
|message|data.rule.ecr_public_access_disable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Public AWS ECR Repository potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_repository_policy']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
