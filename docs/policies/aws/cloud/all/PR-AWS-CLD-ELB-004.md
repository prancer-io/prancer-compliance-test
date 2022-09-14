



# Master Test ID: PR-AWS-CLD-ELB-004


Master Snapshot Id: ['TEST_ELB_05']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-004|
|eval: |data.rule.elb_conn_drain|
|message: |data.rule.elb_conn_drain_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_004.py|


severity: Medium

title: AWS Elastic Load Balancer (Classic) with connection draining disabled

description: This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
