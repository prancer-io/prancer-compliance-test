



# Title: Ensure Athena logging is enabled for athena workgroup.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ATH-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ATH-002|
|eval|data.rule.athena_logging_is_enabled|
|message|data.rule.athena_logging_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#aws-resource-athena-workgroup--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ATH_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if logging is enabled for Athena to detect incidents, receive alerts when incidents occur, and respond to them. logs can be configured via CloudTrail, CloudWatch events and Quicksights for visualization.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::athena::workgroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
