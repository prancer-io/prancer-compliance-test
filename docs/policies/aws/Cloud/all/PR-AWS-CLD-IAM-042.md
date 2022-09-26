



# Title: Ensure IAM policy is attached to group rather than user.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-042

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_04']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-042|
|eval|data.rule.iam_policy_attached_to_user|
|message|data.rule.iam_policy_attached_to_user_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_attached_user_policies' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_042.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It identifies IAM policies attached to user. By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended that IAM policies be applied directly to groups but not users.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure access management', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management', 'Brazilian Data Protection Law (LGPD)-Article 46', 'Brazilian Data Protection Law (LGPD)-Article 6', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-1.16', 'CIS v1.3.0 (AWS)-1.15', 'CIS v1.4.0 (AWS)-1.15', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-06', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IAM-02', 'CSA CCM v3.0.1-IAM-06', 'CSA CCM v3.0.1-IAM-09', 'CSA CCM v3.0.1-IAM-10', 'CSA CCM v3.0.1-IVS-11', 'CSA CCM v3.0.1-STA-01', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 24", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HIPAA', 'HIPAA-164.312(a)(1)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.c', 'HITRUST CSF v9.3-Control Reference:01.s', 'HITRUST CSF v9.3-Control Reference:01.v', 'HITRUST CSF v9.3-Control Reference:01.y', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO 27001', 'ISO 27001:2013-A.9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1078', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST 800', 'NIST 800-171 Rev1-3.1.5', 'NIST 800-171 Rev1-3.1.6', 'NIST 800-171 Rev1-3.1.7', 'NIST 800-53 Rev 5-Least Privilege', 'NIST 800-53 Rev 5-Least Privilege \| Privileged Access by Non-organizational Users', 'NIST 800-53 Rev4-AC-6', 'NIST 800-53 Rev4-AC-6 (6)', 'NIST CSF', 'NIST CSF-DE.CM-3', 'NIST CSF-PR.AC-4', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.3']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
