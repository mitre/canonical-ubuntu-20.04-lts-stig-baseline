control 'SV-238301' do
  title 'The Ubuntu operating system must configure audit tools to be owned by root. '
  desc "Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user enjoys in order to make access
decisions regarding the access to audit tools.

Audit tools include, but are not limited to,
vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

 "
  desc 'check', "Verify the Ubuntu operating system configures the audit tools to be owned by root to prevent
any unauthorized access.

Check the ownership by running the following command:

$ stat -c
\"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd
/sbin/audispd /sbin/augenrules

/sbin/auditctl root
/sbin/aureport root

/sbin/ausearch root
/sbin/autrace root
/sbin/auditd root
/sbin/audispd root

/sbin/augenrules root

If any of the audit tools are not owned by root, this is a finding. "
  desc 'fix', "Configure the audit tools on the Ubuntu operating system to be protected from unauthorized
access by setting the file owner as  root using the following command:

$ sudo chown root
[audit_tool]

Replace \"[audit_tool]\" with each audit tool not owned by root. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000256-GPOS-00097 '
  tag satisfies: %w(SRG-OS-000256-GPOS-00097 SRG-OS-000257-GPOS-00098)
  tag gid: 'V-238301 '
  tag rid: 'SV-238301r654078_rule '
  tag stig_id: 'UBTU-20-010200 '
  tag fix_id: 'F-41470r654077_fix '
  tag cci: %w(CCI-001493 CCI-001494)
  tag nist: ['AU-9 a', 'AU-9']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    audit_tools = input('audit_tools')

    audit_tools.each do |tool|
      describe file(tool) do
        its('owner') { should cmp 'root' }
      end
    end
  end
end
