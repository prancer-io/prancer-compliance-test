



# Title: AWS Redshift does not have require_ssl configured


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-003|
|eval|data.rule.redshift_require_ssl|
|message|data.rule.redshift_require_ssl_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_parameter_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Redshift databases in which data connection to and from is occurring on an insecure channel. SSL connections ensures the security of the data in transit.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-03', 'CSA CCM v3.0.1-EKM-03', 'CSA CCM v3.0.1-IPY-04', 'CSA CCM v3.0.1-IVS-10', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST CSF v9.3-Control Reference:09.x', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO 27001', 'ISO 27001:2013-A.13.1.1', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.6.2.2', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-14.1.2', 'MLPS', 'MLPS 2.0-8.1.2.2', 'NIST 800', 'NIST 800-171 Rev1-3.13.8', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'New Zealand Information Security Manual (NZISM v3.4)-22.1', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC6.7']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_parameter_group']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
