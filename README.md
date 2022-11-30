# canonical-ubuntu-20.04-lts-stig-baseline

InSpec profile to validate the secure configuration of Ubuntu 20.04, against [DISA](https://iase.disa.mil/stigs/)'s Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide (STIG) Version 1, Release 6.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site. 

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
temporary_accounts: []
banner_text: 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
  sudo_accounts: [ "ubuntu" ]
  tmout: 600
  action_mail_acct: root
  audit_tools: [
      '/sbin/auditctl',
      '/sbin/aureport',
      '/sbin/ausearch',
      '/sbin/autrace',
      '/sbin/auditd',
      '/sbin/audispd',
      '/sbin/augenrules'
    ]
  standard_audit_log_size: 8894028
  aide_conf_path: '/etc/aide/aide.conf'
  action_mail_acct: root
  maxlogins: 10
  is_kdump_required: false
  is_system_networked: true
  sssd_conf_path: '/etc/sssd/sssd.conf'
  allowed_ca_fingerprints_regex: (9676F287356C89A12683D65234098CB77C4F1C18F23C0E541DE0E196725B7EBE|B107B33F453E5510F68E513110C6F6944BACC263DF0137F821C1B3C2F8F863D2|559A5189452B13F8233F0022363C06F26E3C517C1D4B77445035959DF3244F74|1F4EDE9DC2A241F6521BF518424ACD49EBE84420E69DAF5BAC57AF1F8EE294A9)
  allowed_network_interfaces: [
      'lo',
      'eth0'
    ]
  audit_sp_remote_server: '192.0.0.1'
  approved_wireless_interfaces: []
  fips_config_file: '/proc/sys/crypto/fips_enabled'
  chrony_config_file: '/etc/chrony/chrony.conf'
  useradd_config_file: '/etc/default/useradd'
  rsyslog_config_file: '/etc/rsyslog.d/50-default.conf'
  auditoffload_config_file: '/etc/cron.weekly/audit-offload'
  audispremote_config_file: '/etc/audisp/plugins.d/au-remote.conf'
  gdm3_config_file: '/etc/gdm3/greeter.dconf-defaults'
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/canonical-ubuntu-20.04-lts-stig-baseline/archive/master.tar.gz --target=ssh://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account> --sudo --sudo-password=<sudo_password_for_target_if_required> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/canonical-ubuntu-20.04-lts-stig-baseline
inspec archive canonical-ubuntu-20.04-lts-stig-baseline
inspec exec <name of generated archive> --target=ssh://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account> --sudo --sudo-password=<sudo_password_for_target_if_required> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd canonical-ubuntu-20.04-lts-stig-baseline
git pull
cd ..
inspec archive canonical-ubuntu-20.04-lts-stig-baseline --overwrite
inspec exec <name of generated archive> --target=ssh://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account> --sudo --sudo-password=<sudo_password_for_target_if_required> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* 

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/canonical-ubuntu-20.04-lts-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
