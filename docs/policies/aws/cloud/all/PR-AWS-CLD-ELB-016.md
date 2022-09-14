



# Master Test ID: PR-AWS-CLD-ELB-016


Master Snapshot Id: ['TEST_ELB_01']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-016|
|eval: |data.rule.elb_subnet|
|message: |data.rule.elb_subnet_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_016.py|


severity: Medium

title: Ensure one of Subnets or SubnetMappings is defined for loadbalancer

description: Ensure one of Subnets or SubnetMappings is defined for loadbalancer  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
