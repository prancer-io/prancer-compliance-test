



# Master Test ID: PR-AWS-CLD-NACL-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01NETWORKACL']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-NACL-001|
|eval|data.rule.acl_all_icmp_ipv4|
|message|data.rule.acl_all_icmp_ipv4_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_NACL_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Network ACLs with Inbound rule to allow All ICMP IPv4

***<font color="white">Description:</font>*** This policy identifies ACLs which allows traffic on all ICMP IPv4 protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'NIST 800']|
|service|['nacl']|



[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2networkacl.rego
