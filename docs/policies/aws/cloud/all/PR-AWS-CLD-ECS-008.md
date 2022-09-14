



# Master Test ID: PR-AWS-CLD-ECS-008


Master Snapshot Id: ['TEST_ECS_01']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-008|
|eval: |data.rule.ecs_container_insight_enable|
|message: |data.rule.ecs_container_insight_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-cluster-clustersettings.html#cfn-ecs-cluster-clustersettings-name' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_008.py|


severity: Low

title: Ensure container insights are enabled on ECS cluster

description: Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
