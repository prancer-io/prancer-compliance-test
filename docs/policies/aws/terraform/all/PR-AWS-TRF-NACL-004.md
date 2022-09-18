



# Title: AWS Network ACLs with Outbound rule to allow All ICMP IPv4


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-NACL-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-NACL-004|
|eval|data.rule.acl_all_icmp_ipv4_out|
|message|data.rule.acl_all_icmp_ipv4_out_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_NACL_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ACLs which allows traffic on all protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_network_acl_rule']


[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2networkacl.rego
