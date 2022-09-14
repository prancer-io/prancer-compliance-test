



# Master Test ID: PR-AWS-CLD-EC2-003


Master Snapshot Id: ['TEST_EC2_01']

type: rego

rule: [file(ec2.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC2-003|
|eval: |data.rule.ec2_public_ip|
|message: |data.rule.ec2_public_ip_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC2_003.py|


severity: Low

title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access

description: This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CIS', 'PCI DSS', 'NIST 800']|
|service: |['ec2']|



[file(ec2.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
