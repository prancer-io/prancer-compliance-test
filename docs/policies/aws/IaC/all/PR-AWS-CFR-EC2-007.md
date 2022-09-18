



# Title: Ensure Amazon Machine Image (AMI) is not infected with mining malware.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EC2-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EC2-007|
|eval|data.rule.ami_not_infected|
|message|data.rule.ami_not_infected_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#aws-properties-ec2-instance--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EC2_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Amazon Machine Images (AMIs) that are infected with mining malware. As per research, AWS Community AMI Windows 2008 hosted by an unverified vendor containing malicious code running an unidentified crypto (Monero) miner. It is recommended to delete such AMIs to protect from malicious activity and attack blast.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1204.003 - User Execution:Malicious Image']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego
