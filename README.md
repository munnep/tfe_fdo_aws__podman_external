# TFE FDO Podman with External Services (S3 + PostgreSQL) and valid certificates

With this repository you will be able to do a TFE FDO (Terraform Enterprise) online installation on AWS with external services for storage in the form of S3 and PostgreSQL and a valid certificate. 

The Terraform code will do the following steps

- Create S3 buckets used for TFE
- Upload the necessary software/files for the TFE installation to an S3 bucket
- Generate TLS certificates with Let's Encrypt to be used by TFE
- Create a VPC network with subnets, security groups, internet gateway
- Create a RDS PostgreSQL to be used by TFE
- create roles/profiles for the TFE instance to access S3 buckets
- Create a EC2 instance on which the TFE online installation will be performed
- Terraform Enterprise will use Podman for managing the TFE container

# Diagram

![](diagram/diagram_external.png)  

# Prerequisites

## AWS
We will be using AWS. Make sure you have the following
- AWS account  
- Install AWS cli [See documentation](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

## Install terraform  
See the following documentation [How to install Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)

## TLS certificate
You need to have valid TLS certificates that can be used with the DNS name you will be using to contact the TFE instance.  
  
The repo assumes you have no certificates and want to create them using Let's Encrypt and that your DNS domain is managed under AWS. 

# How to

- Clone the repository to your local machine
```
git clone https://github.com/munnep/tfe_fdo_aws_podman_external.git
```
- Go to the directory
```
cd tfe_fdo_aws_podman_external
```
- Set your AWS credentials
```
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=
```
- create a file called `variables.auto.tfvars` with the following contents and your own values
```
tag_prefix                 = "patrick-tfe"                        # TAG prefix for names to easily find your AWS resources
region                     = "eu-north-1"                         # Region to create the environment
vpc_cidr                   = "10.234.0.0/16"                      # subnet mask that can be used 
tfe_os                     = "ubuntu"                             # ubuntu or redhat image 
tfe_license                = "<license_key>                       # license key for TFE as string
rds_password               = "Password#1"                         # password used for the RDS environment
dns_hostname               = "patrick-tfe3"                       # DNS hostname for the TFE
dns_zonename               = "bg.hashicorp-success.com"           # DNS zone name to be used
tfe_password               = "Password#1"                         # TFE password for the dashboard and encryption of the data
certificate_email          = "patrick.munne@hashicorp.com"        # Your email address used by TLS certificate registration
public_key                 = "ssh-rsa AAAAB3Nz"                   # The public key used for the accounts
tfe_release                = "v202406-1"
```
- Terraform initialize
```
terraform init
```
- Terraform plan
```
terraform plan
```
- Terraform apply
```
terraform apply
```
- Terraform output should create 37 resources and show you the public dns string you can use to connect to the TFE instance
```
Apply complete! Resources: 37 added, 0 changed, 0 destroyed.

Outputs:

connection_to_servers = "Connect using Session Manager"
tfe_appplication = "https://tfe47.aws.munnep.com"
```
- You can now login to the application with the username admin and password specified in your variables.

# TODO

# DONE
- [x] Create an AWS RDS PostgreSQL
- [x] create a virtual machine in a public network with public IP address.
    - [x] use Redhat
    - [x] firewall inbound are all from user building external ip
    - [x] firewall outbound rules
          postgresql rds
          AWS bucket          
- [x] Create an AWS bucket
- [x] create an elastic IP to attach to the instance
- [x] transfer files to TFE virtual machine
      - license
      - TLS certificates
- [x] Create a valid certificate to use 
- [x] point dns name to public ip address
- [x] build network according to the diagram
- [x] install TFE



