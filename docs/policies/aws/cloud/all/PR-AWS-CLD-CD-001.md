



# Master Test ID: PR-AWS-CLD-CD-001


Master Snapshot Id: ['TEST_CD']

type: rego

rule: [file(code.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CD-001|
|eval: |data.rule.deploy_compute_platform|
|message: |data.rule.deploy_compute_platform_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CD_001.py|


severity: Medium

title: AWS CodeDeploy application compute platform must be ECS or Lambda

description: AWS CodeDeploy application compute platform must be ECS or Lambda  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['SOC 2', 'PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['codedeploy']|



[file(code.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/code.rego
