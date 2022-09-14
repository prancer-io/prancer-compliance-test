



# Master Test ID: PR-AWS-CLD-ATH-002


Master Snapshot Id: ['TEST_ATH']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ATH-002|
|eval: |data.rule.athena_logging_is_enabled|
|message: |data.rule.athena_logging_is_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/athena.html#Athena.Client.get_work_group' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ATH_002.py|


severity: Medium

title: Ensure Athena logging is enabled for athena workgroup.

description: It checks if logging is enabled for Athena to detect incidents, receive alerts when incidents occur, and respond to them. logs can be configured via CloudTrail, CloudWatch events and Quicksights for visualization.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['athena']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
