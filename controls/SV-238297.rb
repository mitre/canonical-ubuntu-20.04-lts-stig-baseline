control 'SV-238297' do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses
of the delete_module syscall. "
  desc "Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

 "
  desc 'check', "Verify the Ubuntu operating system generates an audit record for any
successful/unsuccessful attempts to use the \"delete_module\" syscall.

Check the
currently configured audit rules with the following command:

$ sudo auditctl -l | grep -w
delete_module

-a always,exit -F arch=b32 -S delete_module -F auid&gt;=1000 -F auid!=-1
-k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid&gt;=1000 -F auid!=-1 -k
module_chng

If the command does not return a line that matches the example or the line is
commented out, this is a finding.

Notes:
- For 32-bit architectures, only the 32-bit
specific output lines from the commands are required.
- The \"-k\" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above. "
  desc 'fix', "Configure the audit system to generate an audit event for any successful/unsuccessful use of
the \"delete_module\" syscall.

Add or update the following rules in the
\"/etc/audit/rules.d/stig.rules\" file:

-a always,exit -F arch=b32 -S delete_module -F
auid&gt;=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S
delete_module -F auid&gt;=1000 -F auid!=4294967295 -k module_chng

Notes: For 32-bit
architectures, only the 32-bit specific entries are required.

To reload the rules file,
issue the following command:

$ sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000064-GPOS-00033 '
  tag satisfies: ['SRG-OS-000477-GPOS-00222']
  tag gid: 'V-238297 '
  tag rid: 'SV-238297r802387_rule '
  tag stig_id: 'UBTU-20-010181 '
  tag fix_id: 'F-41466r654065_fix '
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
      describe auditd.syscall('delete_module').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
    describe auditd.syscall('delete_module').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
