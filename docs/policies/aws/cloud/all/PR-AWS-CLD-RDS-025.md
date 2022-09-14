



# Master Test ID: PR-AWS-CLD-RDS-025


Master Snapshot Id: ['TEST_RDS_06']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-025|
|eval: |data.rule.db_snapshot_is_encrypted|
|message: |data.rule.db_snapshot_is_encrypted_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#aws-resource-rds-dbcluster--examples' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_025.py|


severity: Medium

title: Ensure AWS RDS DB snapshot is encrypted.

description: It identifies AWS RDS DB (Relational Database Service Database) cluster snapshots which are not encrypted. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-1.4', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'NIST 800', 'NIST 800-53 Rev 5-Protection of Information at Rest \| Cryptographic Protection', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-28 (1)', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'New Zealand Information Security Manual (NZISM v3.4)-20.4', 'New Zealand Information Security Manual (NZISM v3.4)-22.1', 'PCI DSS v3.2.1-3.4.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68']|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
