



# Master Test ID: PR-AWS-CLD-RDS-031


Master Snapshot Id: ['TEST_RDS_02', 'TEST_KMS']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-031|
|eval: |data.rule.rds_cluster_encrypt_cmk|
|message: |data.rule.rds_cluster_encrypt_cmk_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_031.py|


severity: Medium

title: Ensure AWS RDS DB cluster is not encrypted using default KMS key instead of CMK.

description: It identifies RDS DB(Relational Database Service Database) clusters which are encrypted using default KMS key instead of CMK (Customer Master Key). As a security best practice CMK should be used instead of default KMS key for encryption to gain the ability to rotate the key according to your own policies, delete the key, and control access to the key via KMS policies and IAM policies.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'LGPD', 'CSA CCM', 'CMMC', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI DSS', 'RMiT', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-12', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68']|
|service: |['rds', 'kms']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
