package rule

default rulepass = false


rulepass = true{
	input.Certificate.Options.CertificateTransparencyLoggingPreference="ENABLED"
}

