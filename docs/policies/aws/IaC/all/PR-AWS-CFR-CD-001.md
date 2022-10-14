



# Title: AWS CodeDeploy application compute platform must be ECS or Lambda


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CD-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CD-001|
|eval|data.rule.deploy_compute_platform|
|message|data.rule.deploy_compute_platform_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CD_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** AWS CodeDeploy application compute platform must be ECS or Lambda  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['SOC 2', 'PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::codedeploy::application']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/code.rego
