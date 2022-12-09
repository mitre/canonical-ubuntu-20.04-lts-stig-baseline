control 'SV-238268' do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses
of the chmod, fchmod, and fchmodat system calls. "
  desc "Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

 "
  desc 'check', "Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the \"chmod\", \"fchmod\", and \"fchmodat\" system calls.

Check the configured
audit rules with the following commands:

$ sudo auditctl -l | grep chmod

-a always,exit -F
arch=b32 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=-1 -k perm_chng
-a
always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=-1 -k
perm_chng

If the command does not return audit rules for the \"chmod\", \"fchmod\" and
\"fchmodat\" syscalls or the lines are commented out, this is a finding.

Notes:
For 32-bit
architectures, only the 32-bit specific output lines from the commands are required.
The
\"-k\" allows for specifying an arbitrary identifier, and the string after it does not need to
match the example output above. "
  desc 'fix', "Configure the audit system to generate an audit event for any successful/unsuccessful use of
the \"chmod\", \"fchmod\", and \"fchmodat\" system calls.

Add or update the following rules in
the \"/etc/audit/rules.d/stig.rules\":

-a always,exit -F arch=b32 -S
chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng
-a always,exit
-F arch=b64 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng


Notes: For 32-bit architectures, only the 32-bit specific entries are required.

To
reload the rules file, issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000064-GPOS-00033 '
  tag satisfies: %w(SRG-OS-000064-GPOS-00033 SRG-OS-000462-GPOS-00206)
  tag gid: 'V-238268 '
  tag rid: 'SV-238268r808480_rule '
  tag stig_id: 'UBTU-20-010152 '
  tag fix_id: 'F-41437r808479_fix '
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    if os.arch == 'x86_64'
      describe auditd.syscall('chmod').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
    describe auditd.syscall('chmod').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
