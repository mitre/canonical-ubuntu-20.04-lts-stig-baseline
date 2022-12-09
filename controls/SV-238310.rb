control 'SV-238310' do
  title "The Ubuntu operating system must generate audit records for any successful/unsuccessful
use of unlink, unlinkat, rename, renameat, and rmdir system calls. "
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
one rule whenever possible. "
  desc 'check', "Verify the Ubuntu operating system generates audit records for any
successful/unsuccessful use of \"unlink\", \"unlinkat\", \"rename\", \"renameat\", and \"rmdir\"
system calls.

Check the currently configured audit rules with the following command:

$
sudo auditctl -l | grep 'unlink\\|rename\\|rmdir'

-a always,exit -F arch=b64 -S
unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F auid!=-1 -F key=delete
-a
always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F
auid!=-1 -F key=delete

If the command does not return audit rules for the \"unlink\",
\"unlinkat\", \"rename\", \"renameat\", and \"rmdir\" syscalls or the lines are commented out, this
is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from
the commands are required.
The \"key\" allows for specifying an arbitrary identifier, and the
string after it does not need to match the example output above. "
  desc 'fix', "Configure the audit system to generate audit events for any successful/unsuccessful use of
\"unlink\", \"unlinkat\", \"rename\", \"renameat\", and \"rmdir\" system calls.

Add or update the
following rules in the \"/etc/audit/rules.d/stig.rules\" file:

-a always,exit -F
arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F
auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S
unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F auid!=4294967295 -k delete


Notes: For 32-bit architectures, only the 32-bit specific entries are required.

To
reload the rules file, issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000468-GPOS-00212 '
  tag gid: 'V-238310 '
  tag rid: 'SV-238310r832953_rule '
  tag stig_id: 'UBTU-20-010267 '
  tag fix_id: 'F-41479r832952_fix '
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
      describe auditd.syscall('unlink').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
    describe auditd.syscall('unlink').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
