control 'SV-238372' do
  title 'The Ubuntu operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the System Administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the Ubuntu operating system. Changes to Ubuntu operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) notifies the System Administrator
 when anomalies in the operation of any security functions are discovered with the following command:

$ sudo grep SILENTREPORTS /etc/default/aide

SILENTREPORTS=no

If SILENTREPORTS is uncommented and set to "yes", this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner.

Modify the "SILENTREPORTS" parameter in the "/etc/default/aide" file with a value of "no" if it does not already exist.'
  impact 0.5
  tag check_id: 'C-41582r654289_chk'
  tag severity: 'medium'
  tag gid: 'V-238372'
  tag rid: 'SV-238372r958948_rule'
  tag stig_id: 'UBTU-20-010451'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-41541r654290_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002699', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 b', 'SI-6 d']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  file_integrity_tool = input('file_integrity_tool')

  if file_integrity_tool == 'aide'
    describe file('/etc/default/aide') do
      it { should exist }
      its('content') { should match(/^\s*SILENTREPORTS=(['"]?)no\1\s*$/) }
    end
  else
    describe('Manual review') do
      skip("File integrity tool is '#{file_integrity_tool}', not 'aide'. Manually review the tool's notification configuration.")
    end
  end
end
