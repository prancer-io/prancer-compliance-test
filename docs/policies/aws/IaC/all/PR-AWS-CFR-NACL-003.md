



# Title: AWS Network ACLs with Inbound rule to allow All Traffic


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-NACL-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-NACL-003|
|eval|data.rule.acl_all_traffic|
|message|data.rule.acl_all_traffic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_NACL_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::networkaclentry']


[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego
