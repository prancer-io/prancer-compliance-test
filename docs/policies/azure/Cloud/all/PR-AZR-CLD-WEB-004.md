



# Title: Web App should use the latest version of HTTP


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-004|
|eval|data.rule.http_20_enabled|
|message|data.rule.http_20_enabled_err|
|remediationDescription|1. Sign on to Azure Management console and navigate to App services<br>2. Click on the name of the App service web application you want to examine<br>3. In the navigation panel,under Settings, select Configuration to access the configuration settings defined for the selected application.<br>4. On the Configuration panel, select 'General settings' tab to access the application general settings<br>5. In the Platform settings section, select '2.0' from the HTTP version dropdown list to enable HTTP/2 – the latest version of HTTP protocol,for the selected web application<br>6. Click Save to apply the change<br><br>References:<br><a href='https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions' target='_blank'>https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions</a>|
|remediationFunction|PR_AZR_CLD_WEB_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** We recommend you use the latest HTTP version for web apps and take advantage of any security fixes and new functionalities featured. With each software installation you can determine if a given update meets your organization's requirements. Organizations should verify the compatibility and support provided for any additional software, assessing the current version against the update revision being considered.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-PV-3', 'Azure Security Benchmark (v2)-PV-7', 'Azure Security Benchmark (v3)-AM-2', 'Azure Security Benchmark (v3)-AM-5', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS v1.1 (Azure)-9.10', 'CIS v1.2.0 (Azure)-9.10', 'CIS v1.3.0 (Azure)-9.9', 'CIS v1.3.1 (Azure)-9.9', 'CIS v1.4.0 (Azure)-9.9', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'NIST 800', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1']|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
