



# Title: Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AS-002|
|eval|data.rule.as_elb_health_check|
|message|data.rule.as_elb_health_check_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_AS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_autoscaling_group']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
