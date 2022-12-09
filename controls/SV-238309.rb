control 'SV-238309' do
  title "The Ubuntu operating system must generate audit records for privileged activities,
nonlocal maintenance, diagnostic sessions and other system-level access. "
  desc "If events associated with nonlocal administrative access or diagnostic sessions are not
logged, a major tool for assessing and investigating attacks would not be available.

This
requirement addresses auditing-related issues associated with maintenance tools used
specifically for diagnostic and repair actions on organizational information systems.


Nonlocal maintenance and diagnostic activities are those activities conducted by
individuals communicating through a network, either an external network (e.g., the
internet) or an internal network. Local maintenance and diagnostic activities are those
activities carried out by individuals physically present at the information system or
information system component and not communicating across a network connection.

This
requirement applies to hardware/software diagnostic test equipment or tools. This
requirement does not cover hardware/software components that may support information
system maintenance, yet are a part of the system, for example, the software implementing
\"ping,\" \"ls,\" \"ipconfig,\" or the hardware and software implementing the monitoring port of
an Ethernet switch.

 "
  desc 'check', "Verify the Ubuntu operating system audits activities performed during nonlocal
maintenance and diagnostic sessions.

Check the currently configured audit rules with the
following command:

$ sudo auditctl -l | grep sudo.log

-w /var/log/sudo.log -p wa -k
maintenance

If the command does not return lines that match the example or the lines are
commented out, this is a finding.

Note: The \"-k\" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above. "
  desc 'fix', "Configure the Ubuntu operating system to audit activities performed during nonlocal
maintenance and diagnostic sessions.

Add or update the following rules in the
\"/etc/audit/rules.d/stig.rules\" file:

-w /var/log/sudo.log -p wa -k maintenance

To
reload the rules file, issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000392-GPOS-00172 '
  tag satisfies: %w(SRG-OS-000392-GPOS-00172 SRG-OS-000471-GPOS-00215)
  tag gid: 'V-238309 '
  tag rid: 'SV-238309r853427_rule '
  tag stig_id: 'UBTU-20-010244 '
  tag fix_id: 'F-41478r654101_fix '
  tag cci: %w(CCI-000172 CCI-002884)
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    @audit_file = '/var/log/sudo.log'

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
