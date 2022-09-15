



# Master Test ID: PR-AWS-CLD-CT-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-001|
|eval|data.rule.ct_regions|
|message|data.rule.ct_regions_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS CloudTrail is not enabled in all regions

***<font color="white">Description:</font>*** Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CIS', 'HIPAA', 'PCI DSS', 'NIST 800', 'GDPR']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
