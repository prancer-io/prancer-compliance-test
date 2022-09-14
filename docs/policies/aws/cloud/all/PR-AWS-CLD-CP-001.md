



# Master Test ID: PR-AWS-CLD-CP-001


Master Snapshot Id: ['TEST_CP']

type: rego

rule: [file(code.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CP-001|
|eval: |data.rule.cp_artifact_encrypt|
|message: |data.rule.cp_artifact_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CP_001.py|


severity: High

title: Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled

description: The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'ISO 27001', 'HIPAA', 'NIST 800']|
|service: |['codepipeline']|



[file(code.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/code.rego
