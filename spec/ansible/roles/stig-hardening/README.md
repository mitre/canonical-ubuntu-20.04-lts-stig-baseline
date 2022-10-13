# ubuntu_20.04_STIG

Cookbook to automate STIG implementation for Ubuntu 20.04

## Cookbook variables:

Comnpensating controls may exist that satisfy the STIG requirement for a security measure.  
Variables definded in [vars.yml](vars/main.yml) allow skipping package insatallation where compensating controls exist.

|Name|Default|Description|
|----|:-------:|-----------|
|`install_fips`| `no`|Install FIPs certified kernel, openssh, openssl and strongswan modules. Requires `UBUNTU_ADVANTAGE_PASSWORD` and `UBUNTU_ADVANTAGE_PASSWORD_UPDATES` variables to be set. There are **no compensating control** from FIPS STIG requirement. **Ubuntu 20.04 is not FIPS compliant/certified.**|
|`install_aide`| `yes`|`aide` is an open source host based file and directory integrity checker. `install_aide` can be set to `no` if any other integrity checker (e.g. Tripwire) is installed on the VM instead of being baked into the image.|
|`install_chrony`| `yes`| `chrony` provides fast and accurate time synchronization. `install_chrony` can be set to `no` if any other time synching package (e.g. `timesyncd`) is used.|
|`install_audispd_plugins`|`yes`| `audispd_plugins` like relay audit events to remote machines.  `audispd_plugins` can be set to `no` if any other mechanism of relaying logs to remote server (e.g fluentd) is being used.|
|`remove_existing_ca_certs`|`no`| STIG hardening requires `/etc/ssl/certs` only contain certificate files whose sha256 fingerprint match the fingerprint of DoD PKI-established certificate. If the value is set to `yes`, all other certficates under `/etc/ssl/certs` except DoD CA certs will be deleted.|
|`UBUNTU_ADVANTAGE_PASSWORD`| |Env variable in `<USERNAME>:<PASSWORD>` format required to access Ubunutu `FIPS (ppa:ubuntu-advantage/fips)` private Personal Package Archive(ppa). Required if `install_fips` is set to `yes`.|
|`UBUNTU_ADVANTAGE_PASSWORD_UPDATES`| |Env variable in `<USERNAME>:<PASSWORD>` format required to access Ubunutu `FIPS Updates (ppa:ubuntu-advantage/fips-updates)` private Personal Package Archive(ppa). Required if `install_fips` is set to `yes`.|


## Cloud provider specific tasks:
This repo has been tested on AWS only. 
For setting [cloud provider specific modules](tasks/V-219151.yml#L35-43) refer to https://security-certs.docs.ubuntu.com/en/fips-cloud-containers
