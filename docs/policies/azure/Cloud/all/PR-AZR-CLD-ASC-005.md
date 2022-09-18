



# Title: Security Center should send security alerts notifications to subscription admins


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ASC-005

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_296']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ASC-005|
|eval|data.rule.securitycontacts_alerts_to_admins_enabled|
|message|data.rule.securitycontacts_alerts_to_admins_enabled_err|
|remediationDescription|1. From Defender for Cloud's Environment settings area, select the relevant subscription, and open Email notifications.<br><br2. Define the recipients for your notifications with one or both of these options:<br>From the dropdown list,a) select from the available roles.<br>b) Enter specific email addresses separated by commas. There's no limit to the number of email addresses that you can enter.<br><br>3. To apply the security contact information to your subscription, select Save.<br><br>For more information please click <a href='https://docs.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_ASC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify security centers which dont have configuration enabled to send security alerts notifications to subscription admins and alert if missing.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Security']|



[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/securitycontacts.rego
