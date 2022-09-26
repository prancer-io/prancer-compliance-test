



# Title: Ensure AWS CloudTrail is logging data events for S3 and Lambda.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CT-005

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CT-005|
|eval|data.rule.logging_data_events_for_s3_and_lambda|
|message|data.rule.logging_data_events_for_s3_and_lambda_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CT_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks that CloudTrail data event is enabled for S3 and Lambda.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::cloudtrail::trail']


[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudtrail.rego
