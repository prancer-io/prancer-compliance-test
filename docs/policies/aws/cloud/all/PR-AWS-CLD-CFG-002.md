



# Master Test ID: PR-AWS-CLD-CFG-002


Master Snapshot Id: ['TEST_ALL_10']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFG-002|
|eval: |data.rule.aws_config_configuration_aggregator|
|message: |data.rule.aws_config_configuration_aggregator_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-config-configurationaggregator-accountaggregationsource.html#cfn-config-configurationaggregator-accountaggregationsource-allawsregions' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFG_002.py|


severity: Medium

title: Ensure AWS config is enabled in all regions

description: AWS Config is a web service that performs the configuration management of supported AWS resources within your account and delivers log files to you.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Inventory', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-2.5', 'CIS v1.3.0 (AWS)-3.5', 'CIS v1.4.0 (AWS)-3.5', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-AAC-01', 'CSA CCM v3.0.1-AAC-02', 'CSA CCM v3.0.1-AIS-01', 'CSA CCM v3.0.1-DCS-01', 'CSA CCM v3.0.1-GRM-01', 'CSA CCM v3.0.1-IAM-13', 'CSA CCM v3.0.1-IVS-02', 'CSA CCM v3.0.1-IVS-05', 'CSA CCM v3.0.1-IVS-07', 'CSA CCM v3.0.1-MOS-09', 'CSA CCM v3.0.1-MOS-19', 'CSA CCM v3.0.1-TVM-02', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR', 'GDPR-Article 30', 'GDPR-Article 32', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.h', 'HITRUST CSF v9.3-Control Reference:06.g', 'HITRUST CSF v9.3-Control Reference:06.h', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST CSF v9.3-Control Reference:10.m', 'HITRUST CSF v9.3-Control Reference:11.b', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO 27001', 'ISO 27001:2013-A.12.5.1', 'ISO 27001:2013-A.14.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST 800', 'NIST 800-171 Rev1-3.11.3', 'NIST 800-171 Rev1-3.4.1', 'NIST 800-171 Rev1-3.4.2', 'NIST 800-53 Rev 5-Baseline Configuration \| Automation Support for Accuracy and Currency', 'NIST 800-53 Rev 5-Configuration Settings', 'NIST 800-53 Rev 5-Continuous Monitoring', 'NIST 800-53 Rev 5-System Component Inventory \| Assessed Configurations and Approved Deviations', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning', 'NIST 800-53 Rev4-CA-7d', 'NIST 800-53 Rev4-CM-2 (2)', 'NIST 800-53 Rev4-CM-6c', 'NIST 800-53 Rev4-CM-6d', 'NIST 800-53 Rev4-CM-8 (6)', 'NIST 800-53 Rev4-RA-5b.1', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.AE-3', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-2', 'NIST CSF-DE.CM-3', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-1', 'NIST CSF-DE.DP-2', 'NIST CSF-DE.DP-3', 'NIST CSF-DE.DP-4', 'NIST CSF-DE.DP-5', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.IP-1', 'NIST CSF-PR.IP-7', 'NIST CSF-PR.IP-8', 'NIST CSF-RS.AN-1', 'NIST CSF-RS.CO-3', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service: |['config']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
