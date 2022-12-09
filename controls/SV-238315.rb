control 'SV-238315' do
  title 'The Ubuntu operating system must generate audit records for the /var/log/wtmp file. '
  desc "Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter). "
  desc 'check', "Verify the Ubuntu operating system generates audit records showing start and stop times for
user access to the system via the \"/var/log/wtmp\" file.

Check the currently configured
audit rules with the following command:

$ sudo auditctl -l | grep '/var/log/wtmp'

-w
/var/log/wtmp -p wa -k logins

If the command does not return a line matching the example or
the line is commented out, this is a finding.

Note: The \"-k\" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above. "
  desc 'fix', "Configure the audit system to generate audit events showing start and stop times for user
access via the \"/var/log/wtmp\" file.

Add or update the following rules in the
\"/etc/audit/rules.d/stig.rules\" file:

-w /var/log/wtmp -p wa -k logins

To reload the
rules file, issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000472-GPOS-00217 '
  tag gid: 'V-238315 '
  tag rid: 'SV-238315r654120_rule '
  tag stig_id: 'UBTU-20-010277 '
  tag fix_id: 'F-41484r654119_fix '
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    @audit_file = '/var/log/wtmp'

    audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
    if audit_lines_exist
      describe auditd.file(@audit_file) do
        its('permissions') { should_not cmp [] }
        its('action') { should_not include 'never' }
      end

      @perms = auditd.file(@audit_file).permissions

      @perms.each do |perm|
        describe perm do
          it { should include 'w' }
          it { should include 'a' }
        end
      end
    else
      describe('Audit line(s) for ' + @audit_file + ' exist') do
        subject { audit_lines_exist }
        it { should be true }
      end
    end
  end
end
