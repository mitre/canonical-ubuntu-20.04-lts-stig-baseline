control 'SV-238374' do
  title 'The Ubuntu operating system must have an application firewall enabled. '
  desc "Firewalls protect computers from network attacks by blocking or limiting access to open
network ports. Application firewalls limit which applications are allowed to communicate
over the network. "
  desc 'check', "Verify the Uncomplicated Firewall is enabled on the system by running the following command:


$ systemctl status ufw.service | grep -i \"active:\"

Active: active (exited) since Mon
2016-10-17 12:30:29 CDT; 1s ago

If the above command returns the status as \"inactive\", this
is a finding.

If the Uncomplicated Firewall is not installed, ask the System Administrator
if another application firewall is installed. If no application firewall is installed, this
is a finding. "
  desc 'fix', "Enable the Uncomplicated Firewall by using the following command:

$ sudo systemctl enable
ufw.service

If the Uncomplicated Firewall is not currently running on the system, start it
with the following command:

$ sudo systemctl start ufw.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000480-GPOS-00232 '
  tag gid: 'V-238374 '
  tag rid: 'SV-238374r654297_rule '
  tag stig_id: 'UBTU-20-010454 '
  tag fix_id: 'F-41543r654296_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  describe service('ufw') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
