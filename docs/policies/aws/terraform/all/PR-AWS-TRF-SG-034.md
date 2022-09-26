



# Title: Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SG-034

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SG-034|
|eval|data.rule.ec2_instance_has_restricted_access|
|message|data.rule.ec2_instance_has_restricted_access_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SG_034.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure restrict traffic from unknown IP addresses and limit the access to known hosts, services, or specific entities. NOTE: We are excluding the HTTP-80 and HTTPs-443 web ports as these are Internet-facing ports with legitimate traffic.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_security_group']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego
