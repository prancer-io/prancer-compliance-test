



# Title: Instance is communicating with ports known to mine Bitcoin


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-SG-031

***<font color="white">Master Snapshot Id:</font>*** ['TEST_SG']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SG-031|
|eval|data.rule.bitcoin_ports|
|message|data.rule.bitcoin_ports_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SG_031.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['security group']|



[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
