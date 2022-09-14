



# Master Test ID: PR-AWS-CLD-ELB-018


Master Snapshot Id: ['TEST_ELB_06']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-018|
|eval: |data.rule.elb_type|
|message: |data.rule.elb_type_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_018.py|


severity: Medium

title: Ensure all load balancers created are application load balancers

description: Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
