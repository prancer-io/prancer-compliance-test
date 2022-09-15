



# Master Test ID: PR-AWS-CLD-SG-021


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SG']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SG-021|
|eval|data.rule.port_69|
|message|data.rule.port_69_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SG_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)

***<font color="white">Description:</font>*** This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['security group']|



[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
