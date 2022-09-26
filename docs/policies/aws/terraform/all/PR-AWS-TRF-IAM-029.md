



# Title: Ensure IAM policy is not overly permissive to all traffic for ecs.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-029

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-029|
|eval|data.rule.iam_policy_not_overly_permissive_to_all_traffic_for_ecs|
|message|data.rule.iam_policy_not_overly_permissive_to_all_traffic_for_ecs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_029.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ECS IAM policies that are overly permissive to all traffic. It is recommended that the ECS should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/AmazonECS/latest/userguide/security_iam_id-based-policy-examples.html#security_iam_service-with-iam-policy-best-practices  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
