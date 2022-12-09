control 'SV-238304' do
  title "The Ubuntu operating system must prevent all software from executing at higher privilege
levels than users executing the software and the audit system must be configured to audit the
execution of privileged functions. "
  desc "In certain situations, software applications/programs need to execute with elevated
privileges to perform required functions. However, if the privileges required for
execution are at a higher level than the privileges assigned to organizational users
invoking such applications/programs, those users are indirectly provided with greater
privileges than assigned by the organizations.

Some programs and processes are required
to operate at a higher privilege level and therefore should be excluded from the
organization-defined software list after review.

 "
  desc 'check', "Verify the Ubuntu operating system audits the execution of privilege functions by auditing
the \"execve\" system call.

Check the currently configured audit rules with the following
command:

$ sudo auditctl -l | grep execve

-a always,exit -F arch=b64 -S execve -C
uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F
egid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F
key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv


If the command does not return lines that match the example or the lines are commented out,
this is a finding.

Notes:
- For 32-bit architectures, only the 32-bit specific output
lines from the commands are required.
- The \"-k\" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above. "
  desc 'fix', "Configure the Ubuntu operating system to audit the execution of all privileged functions.


Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

-a
always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F
arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b32 -S
execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C
gid!=egid -F egid=0 -F key=execpriv

Notes: For 32-bit architectures, only the 32-bit
specific entries are required.

To reload the rules file, issue the following command:

$
sudo augenrules --load "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000326-GPOS-00126 '
  tag satisfies: %w(SRG-OS-000326-GPOS-00126 SRG-OS-000327-GPOS-00127)
  tag gid: 'V-238304 '
  tag rid: 'SV-238304r853422_rule '
  tag stig_id: 'UBTU-20-010211 '
  tag fix_id: 'F-41473r654086_fix '
  tag cci: %w(CCI-002233 CCI-002234)
  tag nist: ['AC-6 (8)', 'AC-6 (9)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    if os.arch == 'x86_64'
      describe auditd.syscall('execve').where { arch == 'b64' } do
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end
    end
    describe auditd.syscall('execve').where { arch == 'b32' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
