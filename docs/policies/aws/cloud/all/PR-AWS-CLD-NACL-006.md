



# Master Test ID: PR-AWS-CLD-NACL-006


Master Snapshot Id: ['TEST_EC2_01NETWORKACL']

type: rego

rule: [file(ec2networkacl.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-NACL-006|
|eval: |data.rule.acl_all_traffic_out|
|message: |data.rule.acl_all_traffic_out_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_NACL_006.py|


severity: Medium

title: AWS Network ACLs with Outbound rule to allow All Traffic

description: This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'NIST 800']|
|service: |['nacl']|



[file(ec2networkacl.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2networkacl.rego
