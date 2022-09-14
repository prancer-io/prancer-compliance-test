



# Master Test ID: PR-AWS-CLD-ELB-020


Master Snapshot Id: ['TEST_ELB_07']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-020|
|eval: |data.rule.elb_deletion_protection|
|message: |data.rule.elb_deletion_protection_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_020.py|


severity: Low

title: Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled

description: This policy checks if the ELB is protected against accidental deletion by enabling deletion protection.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
