



# Title: Ensure ECR image scan on push is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECR-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECR-003|
|eval|data.rule.ecr_scan|
|message|data.rule.ecr_scan_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECR_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecr_repository']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecr.rego
