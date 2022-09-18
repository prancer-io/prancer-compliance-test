



# Title: AWS RDS database instance is publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RDS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RDS-002|
|eval|data.rule.rds_public|
|message|data.rule.rds_public_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RDS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-6.30', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', 'CSA CCM v3.0.1-MOS-13', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.m', 'HITRUST CSF v9.3-Control Reference:01.n', 'HITRUST CSF v9.3-Control Reference:01.o', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:05.j', 'HITRUST CSF v9.3-Control Reference:06.e', 'HITRUST CSF v9.3-Control Reference:09.z', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'ISO 27001', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v6.3-T1213', 'MITRE ATT&CK v8.2-T1190', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-171 Rev1-3.1.9', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-53 Rev 5-Boundary Protection', 'NIST 800-53 Rev 5-System Use Notification', 'NIST 800-53 Rev4-AC-8c', 'NIST 800-53 Rev4-SC-7b', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-7', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::rds::dbinstance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
