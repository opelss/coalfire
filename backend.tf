#---------+
# Backend
#---------+

terraform {
  backend "s3" {
    bucket       = "example-bucket"
    key          = "path/to/state"
    use_lockfile = true
    region       = "us-east-1"
  }
}
