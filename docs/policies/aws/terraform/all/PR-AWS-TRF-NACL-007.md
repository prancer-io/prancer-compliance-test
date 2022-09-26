



# Title: Unrestricted Inbound Traffic on Remote Server Administration Ports


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-NACL-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-NACL-007|
|eval|data.rule.acl_unrestricted_admin_port|
|message|data.rule.acl_unrestricted_admin_port_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_NACL_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Check your Amazon VPC Network Access Control Lists (NACLs) for inbound/ingress rules that allow unrestricted traffic (i.e. 0.0.0.0/0) on TCP ports 22 (SSH) and 3389 (RDP) and limit access to trusted IP addresses or IP ranges only in order to implement the Principle of Least Privilege (POLP) and reduce the attack surface at the subnet level.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_network_acl_rule']


[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2networkacl.rego
