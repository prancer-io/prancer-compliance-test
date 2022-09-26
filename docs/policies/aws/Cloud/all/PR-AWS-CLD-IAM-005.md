



# Title: AWS IAM policy allows assume role permission across all services


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-005

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-005|
|eval|data.rule.iam_assume_permission|
|message|data.rule.iam_assume_permission_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-14', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-06', 'CSA CCM v3.0.1-IAM-02', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-06', 'CSA CCM v3.0.1-IVS-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 24", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'GDPR', 'GDPR-Article 32', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:01.c', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1098 - Account Manipulation', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1078', 'MITRE ATT&CK v8.2-T1098', 'MLPS', 'MLPS 2.0-8.1.7.2', 'NIST 800', 'NIST 800-171 Rev1-3.1.1', 'NIST 800-171 Rev1-3.1.2', 'NIST 800-53 Rev 5-Access Enforcement \| Role-based Access Control', 'NIST 800-53 Rev4-AC-3 (7)', 'NIST CSF', 'NIST CSF-DE.CM-7', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.3']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
