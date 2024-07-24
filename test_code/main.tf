terraform {
  cloud {
    hostname = "tfe47.aws.munnep.com"
    organization = "test"

    workspaces {
      name = "test"
    }
  }
}

resource "null_resource" "test" {}

