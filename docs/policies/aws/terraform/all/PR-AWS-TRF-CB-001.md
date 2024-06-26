



# Title: Ensure CodeBuild project Artifact encryption is not disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CB-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CB-001|
|eval|data.rule.codebuild_encryption_disable|
|message|data.rule.codebuild_encryption_disable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CB_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** AWS CodeBuild is a fully managed build service in the cloud. CodeBuild compiles your source code, runs unit tests, and produces artifacts that are ready to deploy. Build artifacts, such as a cache, logs, exported raw test report data files, and build results, are encrypted by default using CMKs for Amazon S3 that are managed by the AWS Key Management Service. If you do not want to use these CMKs, you must create and configure a customer-managed CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'PCI-DSS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_codebuild_project']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/code.rego
