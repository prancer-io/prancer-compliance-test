



# Title: Ensure that CodeBuild projects are encrypted using CMK


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CB-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CB-002|
|eval|data.rule.codebuild_encryption|
|message|data.rule.codebuild_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CB_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'PCI-DSS', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_codebuild_project']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/code.rego
