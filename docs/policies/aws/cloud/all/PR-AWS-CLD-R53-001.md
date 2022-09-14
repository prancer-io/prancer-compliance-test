



# Master Test ID: PR-AWS-CLD-R53-001


Master Snapshot Id: ['TEST_ALL_13']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-R53-001|
|eval: |data.rule.route_healthcheck_disable|
|message: |data.rule.route_healthcheck_disable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_R53_001.py|


severity: Medium

title: Ensure Route53 DNS evaluateTargetHealth is enabled

description: The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['route53']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
