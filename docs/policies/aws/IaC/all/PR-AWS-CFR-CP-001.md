



# Title: Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CP-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CP-001|
|eval|data.rule.cp_artifact_encrypt|
|message|data.rule.cp_artifact_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CP_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'ISO 27001', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::codepipeline::pipeline']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/code.rego
