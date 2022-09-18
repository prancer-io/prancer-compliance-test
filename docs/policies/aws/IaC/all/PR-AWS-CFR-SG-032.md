



# Title: Instance is communicating with ports known to mine Ethereum


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SG-032

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SG-032|
|eval|data.rule.ethereum_ports|
|message|data.rule.ethereum_ports_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SG_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::securitygroup']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego
