



# Title: Ensure VPN gateways is configured with cryptographic algorithm


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-NET-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpngateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-NET-006|
|eval|data.rule.vpn_encrypt|
|message|data.rule.vpn_encrypt_err|
|remediationDescription|Make sure you are following the ARM template guidelines for vpn gateway by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_NET_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. IPsec and IKE protocol standard supports a wide range of cryptographic algorithms in various combinations. If customers do not request a specific combination of cryptographic algorithms and parameters, Azure VPN gateways use a set of default proposals. Typically due to compliance or security requirements, you can now configure your Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. It is thus recommended to use custom policy sets and choose strong cryptography.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'GDPR-Article 25', 'GDPR-Article 32', 'HIPAA', 'HIPAA-164.312(e)(2)(ii)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.j', 'HITRUST CSF v9.3-Control Reference:01.y', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST CSF v9.3-Control Reference:09.s', 'ISO 27001:2013', 'ISO 27001:2013-A.10.1.2', 'ISO 27001:2013-A.13.1.1', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.9.2.5', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1108', 'MITRE ATT&CK v6.3-T1108', 'NIST 800', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS', 'PCI DSS v3.2.1-4.1.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/vpngateways']


[vpngateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vpngateways.rego
