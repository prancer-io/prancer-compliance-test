



# Title: Ensure Route53 DNS evaluateTargetHealth is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-R53-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_13']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-R53-001|
|eval|data.rule.route_healthcheck_disable|
|message|data.rule.route_healthcheck_disable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_R53_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['route53']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
