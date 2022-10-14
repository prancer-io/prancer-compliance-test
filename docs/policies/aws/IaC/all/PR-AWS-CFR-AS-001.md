



# Title: Ensure EBS volumes have encrypted launch configurations


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AS-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AS-001|
|eval|data.rule.as_volume_encrypted|
|message|data.rule.as_volume_encrypted_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::autoscaling::launchconfiguration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
