



# Title: Ensure EBS volumes have encrypted launch configurations


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-AS-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_07']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-AS-001|
|eval|data.rule.as_volume_encrypted|
|message|data.rule.as_volume_encrypted_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_AS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'NIST 800', 'GDPR']|
|service|['auto scaling']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
