



# Master Test ID: PR-AWS-CLD-CFG-003


Master Snapshot Id: ['TEST_ALL_17']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFG-003|
|eval: |data.rule.aws_config_recorder_status|
|message: |data.rule.aws_config_recorder_status_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config.html#ConfigService.Client.describe_configuration_recorders' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFG_003.py|


severity: Medium

title: Ensure AWS Config does not fail to deliver log files

description: This policy identifies AWS Configs failing to deliver its log files to the specified S3 bucket. It happens when it doesn't have sufficient permissions to complete the operation. To deliver information to S3 bucket, AWS Config needs to assume an IAM role that manages the permissions required to access the designated S3 bucket.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66']|
|service: |['config']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
