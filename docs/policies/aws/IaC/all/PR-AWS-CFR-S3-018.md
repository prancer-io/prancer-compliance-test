



# Title: Ensure S3 Bucket has public access blocks


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-018

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-018|
|eval|data.rule.s3_public_access_block|
|message|data.rule.s3_public_access_block_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_018.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure network configuration', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CIS', 'CIS v1.3.0 (AWS)-1.20', 'CIS v1.4.0 (AWS)-2.1.5', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v8.2-T1530', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-19.1', 'New Zealand Information Security Manual (NZISM v3.4)-22.1', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
