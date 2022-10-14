



# Title: Unrestricted Inbound Traffic on Remote Server Administration Ports


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-NACL-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-NACL-007|
|eval|data.rule.acl_unrestricted_admin_port|
|message|data.rule.acl_unrestricted_admin_port_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_NACL_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Check your Amazon VPC Network Access Control Lists (NACLs) for inbound/ingress rules that allow unrestricted traffic (i.e. 0.0.0.0/0) on TCP ports 22 (SSH) and 3389 (RDP) and limit access to trusted IP addresses or IP ranges only in order to implement the Principle of Least Privilege (POLP) and reduce the attack surface at the subnet level.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::networkaclentry']


[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego
