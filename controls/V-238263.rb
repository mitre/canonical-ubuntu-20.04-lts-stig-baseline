# encoding: UTF-8

control 'V-238263' do
  title "The Ubuntu operating system must generate audit records for any use of
the fremovexattr system call."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates an audit record upon
successful/unsuccessful attempts to use the \"fremovexattr\" system call.

    Check the currently configured audit rules with the following command:

    $ sudo auditctl -l | grep fremovexattr

    -a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=-1 -k
perm_mod
    -a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -k
perm_mod
    -a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes:
    - For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    - The \"-k\" allows for specifying an arbitrary identifier, and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"fremovexattr\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F
auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.

    To reload the rules file, issue the following command:

    $ sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206',
'SRG-OS-000466-GPOS-00210', 'SRG-OS-000365-GPOS-00152']
  tag gid: 'V-238263'
  tag rid: 'SV-238263r653964_rule'
  tag stig_id: 'UBTU-20-010147'
  tag fix_id: 'F-41432r653963_fix'
  tag cci: ['CCI-000172', 'CCI-001814']
  tag legacy: []
  tag nist: ['AU-12 c', 'CM-5 (1)']

  if os.arch == "x86_64"
    describe auditd.syscall("fremovexattr").where { arch == "b64" } do
      its("action.uniq") { should eq ["always"] }
      its("list.uniq") { should eq ["exit"] }
    end
  end
  describe auditd.syscall("fremovexattr").where { arch == "b32" } do
    its("action.uniq") { should eq ["always"] }
    its("list.uniq") { should eq ["exit"] }
  end
end

