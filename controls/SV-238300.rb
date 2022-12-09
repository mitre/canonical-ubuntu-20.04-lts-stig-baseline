control 'SV-238300' do
  title 'The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive. '
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
  desc 'check', "Verify the Ubuntu operating system configures the audit tools to have a file permission of
0755 or less to prevent unauthorized access by running the following command:

$ stat -c \"%n
%a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd
/sbin/audispd /sbin/augenrules

/sbin/auditctl 755
/sbin/aureport 755

/sbin/ausearch 755
/sbin/autrace 755
/sbin/auditd 755
/sbin/audispd 755

/sbin/augenrules 755

If any of the audit tools have a mode more permissive than 0755, this
is a finding. "
  desc 'fix', "Configure the audit tools on the Ubuntu operating system to be protected from unauthorized
access by setting the correct permissive mode using the following command:

$ sudo chmod
0755 [audit_tool]

Replace \"[audit_tool]\" with the audit tool that does not have the
correct permissions. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000256-GPOS-00097 '
  tag satisfies: %w(SRG-OS-000256-GPOS-00097 SRG-OS-000257-GPOS-00098)
  tag gid: 'V-238300 '
  tag rid: 'SV-238300r654075_rule '
  tag stig_id: 'UBTU-20-010199 '
  tag fix_id: 'F-41469r654074_fix '
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
        it { should_not be_more_permissive_than('0755') }
      end
    end
  end
end
