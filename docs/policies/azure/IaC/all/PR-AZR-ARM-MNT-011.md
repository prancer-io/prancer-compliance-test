



# Title: log profile should be configured to capture all activities


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-011

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-011|
|eval|data.rule.log_profile_category|
|message|data.rule.log_profile_category_err|
|remediationDescription|For Resource type 'microsoft.insights/logprofiles' make sure categories exists and contains 'Write', 'Action' and 'Delete'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_MNT_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** the categories of the logs. These categories are created as is convenient to the user. Some values are: 'Write', 'Delete', and/or 'Action.' We recommend you configure the log profile to export all activities from the control/management plane.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.insights/logprofiles']


[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/activitylogalerts.rego
