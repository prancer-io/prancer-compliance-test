



# Title: Azure SQL database threat detection alerts should be enabled for all threat types


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-020

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_263']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-020|
|eval|data.rule.dbsec_threat_alert|
|message|data.rule.dbsec_threat_alert_err|
|remediationDescription|Login to Azure Portal. Go to SQL databases. For each DB instance. Click on Auditing & Threat Detection. Set Threat Detection types to All. Note: In order to Set Threat Detection types to All, Make sure Auditing is set to On.|
|remediationFunction|PR_AZR_CLD_SQL_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v3.0.1-BCR-05', 'CSA CCM v3.0.1-BCR-09', 'CSA CCM v3.0.1-GRM-02', 'CSA CCM v3.0.1-GRM-09', 'CSA CCM v3.0.1-GRM-10', 'CSA CCM v3.0.1-STA-06', "CyberSecurity Law of the People's Republic of China-Article 55", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-RM.4.149', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:03.b', 'HITRUST CSF v9.3-Control Reference:03.d', 'HITRUST CSF v9.3-Control Reference:12.b', 'ISO 27001:2013', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.16.1.4', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'NIST 800', 'NIST 800-53 Rev4-RA-3e', 'NIST 800-53 Rev4-SA-11 (2)', 'NIST CSF', 'NIST CSF-DE.AE-4', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-4', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.IP-12', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.11.1', 'NIST SP 800-171 Revision 2-3.11.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-2.2', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Databases']|



[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbsecurityalertpolicies.rego
