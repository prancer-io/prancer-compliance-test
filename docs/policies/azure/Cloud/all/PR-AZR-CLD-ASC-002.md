



# Title: Security Center should have security contact emails configured to get notifications


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ASC-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_296']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ASC-002|
|eval|data.rule.securitycontacts|
|message|data.rule.securitycontacts_err|
|remediationDescription|1. From Defender for Cloud's Environment settings area, select the relevant subscription, and open Email notifications.<br><br2. Define the recipients for your notifications with one or both of these options:<br>From the dropdown list,a) select from the available roles.<br>b) Enter specific email addresses separated by commas. There's no limit to the number of email addresses that you can enter.<br><br>3. To apply the security contact information to your subscription, select Save.<br><br>For more information please click <a href='https://docs.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_ASC_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Security']|



[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/securitycontacts.rego
