



# Title: Ensure AWS S3 bucket has a policy attached.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-024

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-024|
|eval|data.rule.s3_has_a_policy_attached|
|message|data.rule.s3_has_a_policy_attached_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_024.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** S3 access can be defined at IAM and Bucket policy levels. It is recommended to leverage bucket policies as it provide much more granularity. This controls check if a bucket has a custom policy attached to it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI DSS', 'SOC 2']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket', 'aws::s3::bucketpolicy']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
