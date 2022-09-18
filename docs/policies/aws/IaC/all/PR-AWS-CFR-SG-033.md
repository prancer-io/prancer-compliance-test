



# Title: Ensure Security groups has attached to a VPCs


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SG-033

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SG-033|
|eval|data.rule.sg_vpc|
|message|data.rule.sg_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-vpcid' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SG_033.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::securitygroup']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego
