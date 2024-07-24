variable "tag_prefix" {
  description = "default prefix of names"
}

variable "region" {
  description = "region to create the environment"
}

variable "vpc_cidr" {
  description = "which private subnet do you want to use for the VPC. Subnet mask of /16"
}

variable "tfe_license" {
  description = "the TFE license as a string"
}

variable "rds_password" {
  description = "password for the RDS postgres database user"
}

variable "public_key" {
  type        = string
  description = "public to use on the instances"
}

variable "tfe_password" {
  description = "password for tfe user"
}


variable "dns_hostname" {
  description = "DNS hostname"
}

variable "dns_zonename" {
  description = "DNS zonename"
}

variable "certificate_email" {
  description = "email address to register the certificate"
}

variable "terraform_client_version" {
  description = "Terraform client installed on the terraform client machine"
}

variable "tfe_os" {
  description = "The operation system used to install TFE on ubuntu/redhat"
  default = "ubuntu"
}

variable "tfe_release" {
  description = "Which release version of TFE to install"
}
