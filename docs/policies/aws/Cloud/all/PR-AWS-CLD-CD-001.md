



# Title: AWS CodeDeploy application compute platform must be ECS or Lambda


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CD-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_CD']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CD-001|
|eval|data.rule.deploy_compute_platform|
|message|data.rule.deploy_compute_platform_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CD_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** AWS CodeDeploy application compute platform must be ECS or Lambda  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['SOC 2', 'PCI DSS', 'HIPAA', 'NIST 800']|
|service|['codedeploy']|



[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/code.rego
