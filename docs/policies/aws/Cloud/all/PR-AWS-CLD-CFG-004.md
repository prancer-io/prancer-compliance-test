



# Title: Ensure AWS Config includes global resources types (IAM).


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CFG-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_09']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFG-004|
|eval|data.rule.config_includes_global_resources|
|message|data.rule.config_includes_global_resources_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFG_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks that global resource types are included in AWS Config.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['config']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
