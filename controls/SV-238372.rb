control 'SV-238372' do
  title "The Ubuntu operating system must notify designated personnel if baseline configurations
are changed in an unauthorized manner. The file integrity tool must notify the System
Administrator when changes to the baseline configuration or anomalies in the operation of
any security functions are discovered. "
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to
various attacks or allow unauthorized access to the Ubuntu operating system. Changes to
Ubuntu operating system configurations can have unintended side effects, some of which may
be relevant to security.

Detecting such changes and providing an automated response can
help avoid unintended, negative consequences that could ultimately affect the security
state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO and SAs must be
notified via email and/or monitoring system trap when there is an unauthorized modification
of a configuration item. "
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) notifies the System
Administrator
 when anomalies in the operation of any security functions are discovered
with the following command:

$ sudo grep SILENTREPORTS /etc/default/aide


SILENTREPORTS=no

If SILENTREPORTS is uncommented and set to \"yes\", this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to notify designated personnel if baseline
configurations are changed in an unauthorized manner.

Modify the \"SILENTREPORTS\"
parameter in the \"/etc/default/aide\" file with a value of \"no\" if it does not already exist. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000447-GPOS-00201 '
  tag gid: 'V-238372 '
  tag rid: 'SV-238372r853449_rule '
  tag stig_id: 'UBTU-20-010451 '
  tag fix_id: 'F-41541r654290_fix '
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
  tag 'host', 'container'

  describe file('/etc/default/aide') do
    it { should exist }
    its('content') { should match '^SILENTREPORTS=no$' }
  end
end
