control 'SV-238353' do
  title 'The Ubuntu operating system must be configured to preserve log records from failure events. '
  desc "Failure to a known state can address safety or security in accordance with the
mission/business needs of the organization. Failure to a known secure state helps prevent a
loss of confidentiality, integrity, or availability in the event of a failure of the
information system or a component of the system.

Preserving operating system state
information helps to facilitate operating system restart and return to the operational mode
of the organization with least disruption to mission/business processes. "
  desc 'check', "Verify the log service is configured to collect system failure events.

Check that the log
service is installed properly with the following command:

$ dpkg -l | grep rsyslog

ii
rsyslog                                    8.32.0-1ubuntu4                                 amd64        reliable system and kernel logging daemon

If the \"rsyslog\"
package is not installed, this is a finding.

Check that the log service is enabled with the
following command:

$ systemctl is-enabled rsyslog

enabled

If the command above
returns \"disabled\", this is a finding.

Check that the log service is properly running and
active on the system with the following command:

$ systemctl is-active rsyslog

active


If the command above returns \"inactive\", this is a finding. "
  desc 'fix', "Configure the log service to collect failure events.

Install the log service (if the log
service is not already installed) with the following command:

$ sudo apt-get install
rsyslog

Enable the log service with the following command:

$ sudo systemctl enable --now
rsyslog "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000269-GPOS-00103 '
  tag gid: 'V-238353 '
  tag rid: 'SV-238353r654234_rule '
  tag stig_id: 'UBTU-20-010432 '
  tag fix_id: 'F-41522r654233_fix '
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
  tag 'host', 'container'

  describe service('rsyslog') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
