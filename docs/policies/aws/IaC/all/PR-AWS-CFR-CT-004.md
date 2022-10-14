



# Title: CloudTrail trail is not integrated with CloudWatch Log


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CT-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CT-004|
|eval|data.rule.ct_cloudwatch|
|message|data.rule.ct_cloudwatch_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CT_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::cloudtrail::trail']


[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudtrail.rego
