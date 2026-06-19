control 'SV-238318' do
  title 'The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use modprobe command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify if the Ubuntu operating system is configured to audit the execution of the module management program "modprobe" by running the following command:

$ sudo auditctl -l | grep "/sbin/modprobe"

-w /sbin/modprobe -p x -k modules

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the Ubuntu operating system to audit the execution of the module management program "modprobe".

Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file:

-w /sbin/modprobe -p x -k modules

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-41528r654127_chk'
  tag severity: 'medium'
  tag gid: 'V-238318'
  tag rid: 'SV-238318r991586_rule'
  tag stig_id: 'UBTU-20-010296'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-41487r654128_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/sbin/modprobe'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('x')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
