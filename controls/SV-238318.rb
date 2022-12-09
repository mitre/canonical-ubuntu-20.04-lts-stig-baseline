control 'SV-238318' do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful
attempts to use modprobe command. "
  desc "Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter). "
  desc 'check', "Verify if the Ubuntu operating system is configured to audit the execution of the module
management program \"modprobe\" by running the following command:

$ sudo auditctl -l | grep
\"/sbin/modprobe\"

-w /sbin/modprobe -p x -k modules

If the command does not return a line,
or the line is commented out, this is a finding.

Note: The \"-k\" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above. "
  desc 'fix', "Configure the Ubuntu operating system to audit the execution of the module management
program \"modprobe\".

Add or update the following rule in the
\"/etc/audit/rules.d/stig.rules\" file:

-w /sbin/modprobe -p x -k modules

To reload the
rules file, issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000477-GPOS-00222 '
  tag gid: 'V-238318 '
  tag rid: 'SV-238318r654129_rule '
  tag stig_id: 'UBTU-20-010296 '
  tag fix_id: 'F-41487r654128_fix '
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    @audit_file = '/sbin/modprobe'

    audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
    if audit_lines_exist
      describe auditd.file(@audit_file) do
        its('permissions') { should_not cmp [] }
        its('action') { should_not include 'never' }
      end

      @perms = auditd.file(@audit_file).permissions

      @perms.each do |perm|
        describe perm do
          it { should include 'x' }
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
