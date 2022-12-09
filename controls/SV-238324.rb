control 'SV-238324' do
  title 'The Ubuntu operating system must monitor remote access methods. '
  desc "Remote access services, such as those providing remote access to network devices and
information systems, which lack automated monitoring capabilities, increase risk and make
remote user access management difficult at best.

Remote access is access to DoD nonpublic
information systems by an authorized user (or an information system) communicating through
an external, non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

Automated monitoring of remote access
sessions allows organizations to detect cyber attacks and also ensure ongoing compliance
with remote access policies by auditing connection activities of remote access
capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system
components (e.g., servers, workstations, notebook computers, smartphones, and tablets). "
  desc 'check', "Verify that the Ubuntu operating system monitors all remote access methods.

Check that
remote access methods are being logged by running the following command:

$  grep -E -r
'^(auth,authpriv\\.\\*|daemon\\.\\*)' /etc/rsyslog.*

/etc/rsyslog.d/50-default.conf:auth,authpriv.*                        /var/log/auth.log

/etc/rsyslog.d/50-default.conf:daemon.*                        /var/log/messages

If \"auth.*\",
\"authpriv.*\", or \"daemon.*\" are not configured to be logged in at least one of the config
files, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to monitor all remote access methods by adding the
following lines to the \"/etc/rsyslog.d/50-default.conf\" file:

auth.*,authpriv.*
/var/log/secure
daemon.* /var/log/messages

For the changes to take effect, restart the
\"rsyslog\" service with the following command:

$ sudo systemctl restart rsyslog.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000032-GPOS-00013 '
  tag gid: 'V-238324 '
  tag rid: 'SV-238324r832959_rule '
  tag stig_id: 'UBTU-20-010403 '
  tag fix_id: 'F-41493r832958_fix '
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host', 'container'

  options = {
    assignment_regex: /^\s*([^:]*?)\s*\t\s*(.*?)\s*$/,
  }
  config_file = input('rsyslog_config_file')
  auth_setting = parse_config_file(config_file, options).params['auth,authpriv.*']
  daemon_setting = parse_config_file(config_file, options).params['daemon.notice']
  describe auth_setting do
    it { should_not be_nil }
    it { should_not be_empty }
  end
  describe daemon_setting do
    it { should_not be_nil }
    it { should_not be_empty }
  end
end
