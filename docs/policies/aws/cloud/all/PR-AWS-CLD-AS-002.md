



# Master Test ID: PR-AWS-CLD-AS-002


Master Snapshot Id: ['TEST_ALL_08']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AS-002|
|eval: |data.rule.as_elb_health_check|
|message: |data.rule.as_elb_health_check_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AS_002.py|


severity: Medium

title: Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks

description: If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['auto scaling']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
