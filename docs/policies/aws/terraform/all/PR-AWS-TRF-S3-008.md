



# Title: AWS S3 bucket has global view ACL permissions enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-008|
|eval|data.rule.s3_public_acl|
|message|data.rule.s3_public_acl_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Data Protection', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'MLPS', 'MLPS 2.0-8.1.4.2', 'NIST 800', 'NIST 800-53 Rev 5-Least Privilege', 'NIST 800-53 Rev4-AC-6', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
