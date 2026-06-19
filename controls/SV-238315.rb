control 'SV-238315' do
  title 'The Ubuntu operating system must generate audit records for the /var/log/wtmp file.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the Ubuntu operating system generates audit records showing start and stop times for user access to the system via the "/var/log/wtmp" file.

Check the currently configured audit rules with the following command:

$ sudo auditctl -l | grep '/var/log/wtmp'

-w /var/log/wtmp -p wa -k logins

If the command does not return a line matching the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the "/var/log/wtmp" file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/wtmp -p wa -k logins

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-41525r654118_chk'
  tag severity: 'medium'
  tag gid: 'V-238315'
  tag rid: 'SV-238315r991581_rule'
  tag stig_id: 'UBTU-20-010277'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-41484r654119_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/var/log/wtmp'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
