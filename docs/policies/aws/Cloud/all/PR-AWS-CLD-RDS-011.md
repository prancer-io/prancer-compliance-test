



# Title: AWS RDS retention policy less than 7 days


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RDS-011

***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-011|
|eval|data.rule.rds_retention|
|message|data.rule.rds_retention_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_011.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 40', 'CMMC', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 34", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.2.042', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'LGPD', 'MAS TRM', 'MAS TRM 2021-8.4.2', 'MLPS', 'MLPS 2.0-8.1.10.6', 'NIST 800', 'NIST 800-53 Rev 5-Audit Record Retention', 'NIST 800-53 Rev4-DM-2', 'NIST CSF', 'NIST CSF-PR.MA-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.7.1', 'NIST SP 800-172-3.1.1e', 'PCI DSS v3.2.1-3.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.5.2', 'RMiT', 'Risk Management in Technology (RMiT)-10.3']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
