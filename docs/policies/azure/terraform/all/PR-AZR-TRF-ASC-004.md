



# Title: Security Center shoud have security contact phone number configured to get notifications


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-ASC-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ASC-004|
|eval|data.rule.securitycontacts_phone|
|message|data.rule.securitycontacts_phone_err|
|remediationDescription|In 'azurerm_security_center_contact' resource, set a valid phone number at 'phone' property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ASC_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Setting a valid phone number in Security contact phone will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CIS', 'CIS v1.1 (Azure)-2.17', 'CSA CCM', 'CSA CCM v3.0.1-AAC-01', 'CSA CCM v3.0.1-AAC-02', 'CSA CCM v3.0.1-BCR-01', 'CSA CCM v3.0.1-BCR-09', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-DCS-01', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-SEF-01', 'CSA CCM v3.0.1-SEF-03', 'CSA CCM v3.0.1-STA-02', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.214', 'GDPR-Article 30', 'GDPR-Article 32', 'GDPR-Article 46', 'HIPAA', 'HIPAA-164.308(a)(6)(ii)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.h', 'HITRUST CSF v9.3-Control Reference:06.g', 'HITRUST CSF v9.3-Control Reference:06.h', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST CSF v9.3-Control Reference:09.ae', 'HITRUST CSF v9.3-Control Reference:10.c', 'HITRUST CSF v9.3-Control Reference:10.m', 'HITRUST CSF v9.3-Control Reference:11.b', 'ISO 27001:2013', 'ISO 27001:2013-A.12.4.3', 'ISO 27001:2013-A.16.1.2', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'NIST 800', 'NIST 800-53 Rev4-AU-5 (2)', 'NIST 800-53 Rev4-CA-7g', 'NIST 800-53 Rev4-CP-2a.3', 'NIST 800-53 Rev4-IR-6 (2)', 'NIST 800-53 Rev4-IR-9 (1)', 'NIST 800-53 Rev4-SI-4 (5)', 'NIST 800-53 Rev4-SI-7 (2)', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.AE-3', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-2', 'NIST CSF-DE.CM-3', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-1', 'NIST CSF-DE.DP-2', 'NIST CSF-DE.DP-3', 'NIST CSF-DE.DP-4', 'NIST CSF-DE.DP-5', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-PR.IP-7', 'NIST CSF-PR.IP-8', 'NIST CSF-RS.AN-1', 'NIST CSF-RS.CO-3', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.9', 'NIST SP 800-171 Revision 2-3.14.3', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-12.10.1', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_security_center_contact']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
