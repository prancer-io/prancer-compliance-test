



# Title: AWS Security Groups allow internet traffic from internet to FTP-Data port (20)


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SG-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SG-006|
|eval|data.rule.port_20|
|message|data.rule.port_20_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SG_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_security_group', 'aws_security_group_rule']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego