



# Title: log profile should be configured to capture all activities


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-MNT-011

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_501']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-MNT-011|
|eval|data.rule.log_profile_category|
|message|data.rule.log_profile_category_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_MNT_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** the categories of the logs. These categories are created as is convenient to the user. Some values are: 'Write', 'Delete', and/or 'Action.' We recommend you configure the log profile to export all activities from the control/management plane.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Management and governance']|



[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/activitylogalerts.rego
