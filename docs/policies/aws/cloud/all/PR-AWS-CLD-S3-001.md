



# Master Test ID: PR-AWS-CLD-S3-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-001|
|eval|data.rule.s3_accesslog|
|message|data.rule.s3_accesslog_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Access logging not enabled on S3 buckets

***<font color="white">Description:</font>*** Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-06', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 40", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'GDPR', 'GDPR-Article 30', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:10.k', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST 800', 'NIST 800-171 Rev1-3.4.5', 'NIST 800-53 Rev 5-Access Restrictions for Change \| Automated Access Enforcement and Audit Records', 'NIST 800-53 Rev4-CM-5 (1)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.1', 'PCI DSS v3.2.1-10.2.3', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC8.1']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
