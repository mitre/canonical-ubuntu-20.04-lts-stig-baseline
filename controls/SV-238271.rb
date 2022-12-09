control 'SV-238271' do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses
of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls. "
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
  desc 'check', "Verify the Ubuntu operating system generates an audit record upon unsuccessful attempts to
use the \"creat\", \"open\", \"openat\", \"open_by_handle_at\", \"truncate\", and \"ftruncate\"
system calls.

Check the configured audit rules with the following commands:

$ sudo
auditctl -l | grep 'open\\|truncate\\|creat'

-a always,exit -F arch=b32 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b32 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=-1 -k perm_access

If the command does not return audit rules for the
\"creat\", \"open\", \"openat\", \"open_by_handle_at\", \"truncate\", and \"ftruncate\" syscalls or
the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the
32-bit specific output lines from the commands are required.
The \"-k\" allows for specifying
an arbitrary identifier, and the string after it does not need to match the example output
above. "
  desc 'fix', "Configure the audit system to generate an audit event for any unsuccessful use of the\"creat\",
\"open\", \"openat\", \"open_by_handle_at\", \"truncate\", and \"ftruncate\" system calls.

Add
or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

-a
always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F
exit=-EPERM -F auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F
arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES
-F auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=4294967295 -k perm_access

Notes: For 32-bit architectures, only
the 32-bit specific entries are required.

To reload the rules file, issue the following
command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000064-GPOS-00033 '
  tag satisfies: %w(SRG-OS-000064-GPOS-00033 SRG-OS-000474-GPOS-00219)
  tag gid: 'V-238271 '
  tag rid: 'SV-238271r808483_rule '
  tag stig_id: 'UBTU-20-010155 '
  tag fix_id: 'F-41440r808482_fix '
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
      describe auditd.syscall('open').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('exit.uniq') { should include '-EPERM' }
      end
      describe auditd.syscall('open').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
        its('exit.uniq') { should include '-EACCES' }
      end
    end
    describe auditd.syscall('open').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('exit.uniq') { should include '-EPERM' }
    end
    describe auditd.syscall('open').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('exit.uniq') { should include '-EACCES' }
    end
  end
end
