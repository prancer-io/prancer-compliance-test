



# Title: AWS Config must record all possible resources


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CFG-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_09']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFG-001|
|eval|data.rule.config_all_resource|
|message|data.rule.config_all_resource_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFG_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-AAC-01', 'CSA CCM v3.0.1-AAC-02', 'CSA CCM v3.0.1-AIS-01', 'CSA CCM v3.0.1-GRM-01', 'CSA CCM v3.0.1-IAM-13', 'CSA CCM v3.0.1-IVS-05', 'CSA CCM v3.0.1-IVS-07', 'CSA CCM v3.0.1-MOS-19', 'CSA CCM v3.0.1-TVM-02', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR', 'GDPR-Article 30', 'GDPR-Article 32', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.h', 'HITRUST CSF v9.3-Control Reference:06.g', 'HITRUST CSF v9.3-Control Reference:06.h', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST CSF v9.3-Control Reference:10.m', 'HITRUST CSF v9.3-Control Reference:11.b', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO 27001', 'ISO 27001:2013-A.12.5.1', 'ISO 27001:2013-A.14.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MLPS', 'MLPS 2.0-8.1.5.4', 'MLPS 2.0-8.2.3.3', 'NIST 800', 'NIST 800-171 Rev1-3.11.2', 'NIST 800-171 Rev1-3.11.3', 'NIST 800-171 Rev1-3.12.1', 'NIST 800-171 Rev1-3.12.2', 'NIST 800-171 Rev1-3.12.3', 'NIST 800-171 Rev1-3.12.4', 'NIST 800-171 Rev1-3.4.1', 'NIST 800-171 Rev1-3.4.2', 'NIST 800-53 Rev 5-Baseline Configuration \| Automation Support for Accuracy and Currency', 'NIST 800-53 Rev 5-Configuration Settings', 'NIST 800-53 Rev 5-Continuous Monitoring', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning', 'NIST 800-53 Rev4-CA-7d', 'NIST 800-53 Rev4-CM-2 (2)', 'NIST 800-53 Rev4-CM-6c', 'NIST 800-53 Rev4-CM-6d', 'NIST 800-53 Rev4-RA-5b.1', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.AE-3', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-2', 'NIST CSF-DE.CM-3', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.DP-1', 'NIST CSF-DE.DP-2', 'NIST CSF-DE.DP-3', 'NIST CSF-DE.DP-4', 'NIST CSF-DE.DP-5', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.IP-7', 'NIST CSF-PR.IP-8', 'NIST CSF-RS.CO-3', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['config']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
