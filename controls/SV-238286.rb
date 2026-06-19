control 'SV-238286' do
  title 'The Ubuntu operating system must generate audit records for the use and modification of faillog file.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful modifications to the "faillog" file.

Check the currently configured audit rules with the following command:

$ sudo auditctl -l | grep faillog

-w /var/log/faillog -p wa -k logins

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "faillog" file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/faillog -p wa -k logins

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-41496r654031_chk'
  tag severity: 'medium'
  tag gid: 'V-238286'
  tag rid: 'SV-238286r958446_rule'
  tag stig_id: 'UBTU-20-010170'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-41455r654032_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000064-GPOS-00033']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/var/log/faillog'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
