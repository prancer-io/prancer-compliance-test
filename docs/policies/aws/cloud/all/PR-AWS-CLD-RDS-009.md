



# Master Test ID: PR-AWS-CLD-RDS-009


Master Snapshot Id: ['TEST_RDS_01']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-009|
|eval: |data.rule.rds_backup|
|message: |data.rule.rds_backup_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_009.py|


severity: Low

title: AWS RDS instance without Automatic Backup setting

description: This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 46', 'CIS', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-3.7', 'CMMC', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 34", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-RE.3.139', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1536', 'MITRE ATT&CK v8.2-T1578.004', 'MLPS', 'MLPS 2.0-8.1.10.11', 'NIST 800', 'NIST 800-53 Rev 5-System Backup', 'NIST 800-53 Rev4-CP-9', 'NIST CSF', 'NIST CSF-PR.MA-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.7.1', 'NIST SP 800-172-3.1.1e', 'PCI DSS v3.2.1-3.1', 'PCI-DSS']|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
