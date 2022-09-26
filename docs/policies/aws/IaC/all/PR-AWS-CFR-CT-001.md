



# Title: AWS CloudTrail is not enabled in all regions


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CT-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CT-001|
|eval|data.rule.ct_regions|
|message|data.rule.ct_regions_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CT_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::cloudtrail::trail']


[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudtrail.rego
