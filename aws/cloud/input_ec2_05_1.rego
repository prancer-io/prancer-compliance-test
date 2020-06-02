package rule

default rulepass = false

rulepass = true{
  instance := input.Reservations[_].Instances[_]
  instance.IamInstanceProfile.Arn
}

# The condition instance.IamInstanceProfile.Arn will be true, if the value exists in the ec2 collection created. 
# Therefore the test case will pass.