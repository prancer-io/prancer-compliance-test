



# Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC2-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC2-003|
|eval|data.rule.ec2_public_ip|
|message|data.rule.ec2_public_ip_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC2_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'PCI-DSS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego
