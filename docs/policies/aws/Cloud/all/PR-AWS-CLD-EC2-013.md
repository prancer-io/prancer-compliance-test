



# Title: Ensure AWS EC2 instance is configured with Instance Metadata Service v2 (IMDSv2).


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC2-013

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-013|
|eval|data.rule.ec2_instance_configured_with_instance_metadata_service_v2|
|message|data.rule.ec2_instance_configured_with_instance_metadata_service_v2_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies AWS instances that are not configured with Instance Metadata Service v2 (IMDSv2). With IMDSv2, every request is now protected by session authentication. IMDSv2 protects against misconfigured-open website application firewalls, misconfigured-open reverse proxies, unpatched SSRF vulnerabilities, and misconfigured-open layer-3 firewalls and network address translation. It is recommended to use only IMDSv2 for all your EC2 instances. For more details:https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure network configuration', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1580 - Cloud Infrastructure Discovery', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-19.1']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
