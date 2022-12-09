control 'SV-238355' do
  title 'The Ubuntu operating system must enable and run the uncomplicated firewall(ufw). '
  desc "Remote access services, such as those providing remote access to network devices and
information systems, which lack automated control capabilities, increase risk and make
remote user access management difficult at best.

Remote access is access to DoD nonpublic
information systems by an authorized user (or an information system) communicating through
an external, non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

Ubuntu operating system functionality
(e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized
activity. Automated control of remote access sessions allows organizations to ensure
ongoing compliance with remote access policies by enforcing connection rules of remote
access applications on a variety of information system components (e.g., servers,
workstations, notebook computers, smartphones, and tablets). "
  desc 'check', "Verify the Uncomplicated Firewall is enabled on the system by running the following command:


$ systemctl is-enabled ufw

If the above command returns the status as \"disabled\", this is
a finding.

Verify the Uncomplicated Firewall is active on the system by running the
following command:

$ systemctl is-active ufw

If the above command returns \"inactive\" or
any kind of error, this is a finding.

If the Uncomplicated Firewall is not installed, ask the
System Administrator if another application firewall is installed.

If no application
firewall is installed, this is a finding. "
  desc 'fix', "Enable the Uncomplicated Firewall by using the following command:

$ sudo systemctl enable
--now ufw.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000297-GPOS-00115 '
  tag gid: 'V-238355 '
  tag rid: 'SV-238355r853430_rule '
  tag stig_id: 'UBTU-20-010434 '
  tag fix_id: 'F-41524r654239_fix '
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
  tag 'host', 'container'

  describe service('ufw') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
