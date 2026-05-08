control 'SV-274858' do
  title 'Ubuntu 20.04 LTS must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify the operating system restricts privilege elevation to authorized personnel with the following command:

$ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Configure the operating system to restrict privilege elevation to authorized personnel.

Remove the following entries from the /etc/sudoers file or any configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag check_id: 'C-78959r1106124_chk'
  tag severity: 'medium'
  tag gid: 'V-274858'
  tag rid: 'SV-274858r1106125_rule'
  tag stig_id: 'UBTU-20-010017'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-78864r1101694_fix'
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container'

  only_if('This controls is not Applicable as sudo is not installed', impact: 0.0) do
    package('sudo').installed?
  end

  describe sudoers(['/etc/sudoers', '/etc/sudoers.d/*']).rules.where { users == 'ALL' && hosts == 'ALL' && !run_as.nil? && ['ALL', 'ALL:ALL'].include?(run_as) && tags.nil? && commands == 'ALL' } do
    its('count') { should eq 0 }
  end
end
