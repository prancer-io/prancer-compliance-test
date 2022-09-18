



# Title: AWS Redshift instances are not encrypted


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-004|
|eval|data.rule.redshift_encrypt|
|message|data.rule.redshift_encrypt_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-EKM-02', 'CSA CCM v3.0.1-EKM-03', 'CSA CCM v3.0.1-EKM-04', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'Firmware, and Information Integrity', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.j', 'HITRUST CSF v9.3-Control Reference:01.v', 'HITRUST CSF v9.3-Control Reference:01.y', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST CSF v9.3-Control Reference:06.f', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST CSF v9.3-Control Reference:09.s', 'HITRUST CSF v9.3-Control Reference:09.x', 'HITRUST CSF v9.3-Control Reference:10.f', 'ISO 27001', 'ISO 27001:2013-A.10.1.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.1.13', 'NIST 800-171 Rev1-3.13.11', 'NIST 800-53 Rev 5-Cryptographic Protection', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev 5-Software', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-13', 'NIST 800-53 Rev4-SI-7 (6)', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC6.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
