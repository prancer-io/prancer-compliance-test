



# Title: Instance is communicating with ports known to mine Bitcoin


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SG-031

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SG-031|
|eval|data.rule.bitcoin_ports|
|message|data.rule.bitcoin_ports_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SG_031.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_security_group', 'aws_security_group_rule']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego
