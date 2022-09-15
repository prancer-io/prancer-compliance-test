



# Master Test ID: PR-AWS-CLD-CP-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CP']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CP-001|
|eval|data.rule.cp_artifact_encrypt|
|message|data.rule.cp_artifact_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CP_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled

***<font color="white">Description:</font>*** The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'ISO 27001', 'HIPAA', 'NIST 800']|
|service|['codepipeline']|



[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/code.rego
