



# Title: Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AS-002|
|eval|data.rule.as_elb_health_check|
|message|data.rule.as_elb_health_check_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::autoscaling::autoscalinggroup']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
