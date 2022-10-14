



# Title: Ensure that SecretsManager RotationSchedule HostedRotationLambda attaches to a VPC Subnet IDs


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SM-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SM-002|
|eval|data.rule.secret_manager_vpc_subnet_id|
|message|data.rule.secret_manager_vpc_subnet_id_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SM_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SecretsManager RotationSchedules should use Subnet IDs  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::secretsmanager::rotationschedule']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
