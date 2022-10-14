



# Title: Ensure ECR resources are accessible only via private endpoint.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-006|
|eval|data.rule.ecr_accessible_only_via_private_endpoint|
|message|data.rule.ecr_accessible_only_via_private_endpoint_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_repository_policy']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
