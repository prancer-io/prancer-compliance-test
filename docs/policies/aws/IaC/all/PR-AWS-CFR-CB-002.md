



# Title: Ensure that CodeBuild projects are encrypted using CMK


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CB-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CB-002|
|eval|data.rule.codebuild_encryption|
|message|data.rule.codebuild_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#cfn-codebuild-project-encryptionkey' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CB_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'PCI-DSS', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::codebuild::project']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/code.rego
