



# Title: activity log retention should be set to 365 days or greater


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-009

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-009|
|eval|data.rule.log_profiles_retention_days|
|message|data.rule.log_profiles_retention_days_err|
|remediationDescription|For Resource type 'microsoft.insights/logprofiles' make sure retentionPolicy.days exists and greater than 365 and retentionPolicy.enabled exists and the value is set to true or retentionPolicy.days exists and set to 0 and retentionPolicy.enabled exists and the value is set to false.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_MNT_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Specifies the retention policy for the log. We recommend you set activity log retention for 365 days or greater. (A value of 0 will retain the events indefinitely.)  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 40', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-5.1.2', 'CSA CCM', 'CSA CCM v3.0.1-BCR-11', 'CSA CCM v3.0.1-GRM-01', 'CSA CCM v3.0.1-MOS-19', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.2.042', 'HIPAA', 'HIPAA-164.312(b)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:06.c', 'HITRUST CSF v9.3-Control Reference:06.d', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST CSF v9.3-Control Reference:09.q', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST CSF v9.3-Control Reference:11.e', 'ISO/IEC 27002:2013', 'ISO/IEC 27001:2013-A.12.4.2', 'ISO/IEC 27001:2013-A.18.1.3', 'NIST 800', 'NIST 800-53 Rev4-AU-11', 'NIST 800-53 Rev4-CM-2 (3)', 'NIST 800-53 Rev4-SI-12', 'NIST CSF', 'NIST CSF-PR.IP-2', 'NIST SP', 'NIST SP 800', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-10.7', 'PIPEDA', 'PIPEDA-4.5.2', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.insights/logprofiles']


[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/activitylogalerts.rego
