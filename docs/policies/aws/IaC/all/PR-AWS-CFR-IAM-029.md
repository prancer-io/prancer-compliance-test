



# Title: Ensure IAM policy is not overly permissive to all traffic for ecs.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-029

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-029|
|eval|data.rule.iam_policy_not_overly_permissive_to_all_traffic_for_ecs|
|message|data.rule.iam_policy_not_overly_permissive_to_all_traffic_for_ecs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_029.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ECS IAM policies that are overly permissive to all traffic. It is recommended that the ECS should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/AmazonECS/latest/userguide/security_iam_id-based-policy-examples.html#security_iam_service-with-iam-policy-best-practices  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
