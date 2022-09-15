



# Master Test ID: PR-AWS-CLD-ELB-004


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_05']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-004|
|eval|data.rule.elb_conn_drain|
|message|data.rule.elb_conn_drain_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Elastic Load Balancer (Classic) with connection draining disabled

***<font color="white">Description:</font>*** This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
