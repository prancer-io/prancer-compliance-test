



# Master Test ID: PR-AWS-CLD-ECS-018


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-018|
|eval|data.rule.ecs_configured_with_active_services|
|message|data.rule.ecs_configured_with_active_services_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_018.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure AWS ECS cluster is configured with active services.

***<font color="white">Description:</font>*** This policy identifies ECS clusters that are not configured with active services. ECS service enables you to run and maintain a specified number of instances of a task definition simultaneously in an Amazon ECS cluster. It is recommended to remove Idle ECS clusters to reduce the container attack surface or create new services for the reported ECS cluster. For details:https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2']|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
