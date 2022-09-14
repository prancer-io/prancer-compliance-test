



# Master Test ID: PR-AWS-CLD-SG-033


Master Snapshot Id: ['TEST_SG']

type: rego

rule: [file(securitygroup.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SG-033|
|eval: |data.rule.sg_vpc|
|message: |data.rule.sg_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-vpcid' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SG_033.py|


severity: Medium

title: Ensure Security groups has attached to a VPCs

description: Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['security group']|



[file(securitygroup.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
