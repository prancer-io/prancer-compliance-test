



# Master Test ID: PR-AWS-CLD-ELB-021


Master Snapshot Id: ['TEST_ELB_06']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-021|
|eval: |data.rule.elb_gateway_load_balancer|
|message: |data.rule.elb_gateway_load_balancer_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_021.py|


severity: Medium

title: Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used

description: This policy checks if Gateway LB is being used or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
