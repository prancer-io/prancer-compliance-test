



# Title: AWS S3 CloudTrail buckets for which access logging is disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-006|
|eval|data.rule.s3_cloudtrail|
|message|data.rule.s3_cloudtrail_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies S3 CloudTrail buckets for which access is disabled.S3 Bucket access logging generates access records for each request made to your S3 bucket. An access log record contains information such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-2.6', 'CIS v1.3.0 (AWS)-3.6', 'CIS v1.4.0 (AWS)-3.6', 'CSA CCM', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-06', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'GDPR', 'GDPR-Article 30', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST 800', 'NIST 800-171 Rev1-3.4.5', 'NIST 800-53 Rev 5-Access Restrictions for Change \| Automated Access Enforcement and Audit Records', 'NIST 800-53 Rev4-CM-5 (1)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'SOC 2', 'SOC 2-CC8.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudtrail']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
