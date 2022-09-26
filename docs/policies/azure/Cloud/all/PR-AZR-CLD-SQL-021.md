



# Title: Threat Detection alert should be configured to send notifications to the SQL server account administrators


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-021

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_263']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-021|
|eval|data.rule.sql_alert|
|message|data.rule.sql_alert_err|
|remediationDescription|Log in to Azure Portal. Go to SQL databases (Left Panel). Choose the reported each DB instance. Under Security section, Click on 'Advanced Threat Protection'. Click on Settings. Select 'Enable Advanced Threat Protection at the database level'. Click on 'Threat Detection settings for this database'. On 'Send alerts to' textbox provide email ID on which you would like to receive alert notifications and Click on the checkbox of 'Email service and co-administrators'. Click on 'Ok' for Threat Detection database settings. Click on 'Save'|
|remediationFunction|PR_AZR_CLD_SQL_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that threat detection alert is configured to send notifications to the sql server account administrators  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'LGPD', 'Brazilian Data Protection Law (LGPD)-Article 46', 'Brazilian Data Protection Law (LGPD)-Article 6', 'CSA CCM', 'CSA CCM v3.0.1-AAC-01', 'CSA CCM v3.0.1-AAC-02', 'CSA CCM v3.0.1-BCR-01', 'CSA CCM v3.0.1-BCR-09', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-DCS-01', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-SEF-01', 'CSA CCM v3.0.1-SEF-03', 'CSA CCM v3.0.1-STA-02', "CyberSecurity Law of the People's Republic of China-Article 55", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'GDPR', 'GDPR-Article 30', 'GDPR-Article 32', 'GDPR-Article 46', 'HIPAA', 'HIPAA-164.308(a)(6)(ii)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.h', 'HITRUST CSF v9.3-Control Reference:06.g', 'HITRUST CSF v9.3-Control Reference:06.h', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST CSF v9.3-Control Reference:09.ae', 'HITRUST CSF v9.3-Control Reference:10.c', 'HITRUST CSF v9.3-Control Reference:10.m', 'HITRUST CSF v9.3-Control Reference:11.b', 'ISO 27001:2013', 'ISO 27001:2013-A.12.4.3', 'ISO 27001:2013-A.16.1.2', 'ISO 27001:2013-A.18.1.3', 'NIST 800', 'NIST 800-53 Rev4-AU-5 (2)', 'NIST 800-53 Rev4-CA-7g', 'NIST 800-53 Rev4-CP-2a.3', 'NIST 800-53 Rev4-IR-6 (2)', 'NIST 800-53 Rev4-IR-9 (1)', 'NIST 800-53 Rev4-SI-4 (5)', 'NIST 800-53 Rev4-SI-7 (2)', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.AE-3', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-2', 'NIST CSF-DE.CM-3', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-1', 'NIST CSF-DE.DP-2', 'NIST CSF-DE.DP-3', 'NIST CSF-DE.DP-4', 'NIST CSF-DE.DP-5', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.IP-7', 'NIST CSF-PR.IP-8', 'NIST CSF-RS.AN-1', 'NIST CSF-RS.CO-3', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.9', 'NIST SP 800-171 Revision 2-3.14.3', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-12.10.1', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['Databases']|



[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbsecurityalertpolicies.rego
