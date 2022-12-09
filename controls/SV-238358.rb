control 'SV-238358' do
  title "The Ubuntu operating system must notify designated personnel if baseline configurations
are changed in an unauthorized manner. The file integrity tool must notify the System
Administrator when changes to the baseline configuration or anomalies in the oper "
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to
various attacks or allow unauthorized access to the operating system. Changes to operating
system configurations can have unintended side effects, some of which may be relevant to
security.

Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security state of the
operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or
monitoring system trap when there is an unauthorized modification of a configuration item. "
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) notifies the System
Administrator
 when anomalies in the operation of any security functions are discovered
with the following command:

$ grep SILENTREPORTS /etc/default/aide

SILENTREPORTS=no


If SILENTREPORTS is commented out, this is a finding.

If SILENTREPORTS is set to \"yes\",
this is a finding.

If SILENTREPORTS is not set to \"no\", this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to notify designated personnel if baseline
configurations are changed in an unauthorized manner.

Modify the \"SILENTREPORTS\"
parameter in the \"/etc/default/aide\" file with a value of \"no\" if it does not already exist. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000363-GPOS-00150 '
  tag gid: 'V-238358 '
  tag rid: 'SV-238358r853433_rule '
  tag stig_id: 'UBTU-20-010437 '
  tag fix_id: 'F-41527r654248_fix '
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
  tag 'host', 'container'

  describe file('/etc/default/aide') do
    it { should exist }
    its('content') { should match '^SILENTREPORTS=no$' }
  end
end
