# encoding: UTF-8

control 'V-238314' do
  title "The Ubuntu operating system must generate audit records when loading
dynamic kernel modules."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates an audit record when adding
and deleting kernel modules.

    Check the currently configured audit rules with the following command:

    $ sudo auditctl -l | grep -delete_module

    always,exit -F arch=b32 -S delete_module -k modules
    always,exit -F arch=b64 -S delete_module -k modules

    If the command does not return lines that matches the example or the lines
are commented out, this is a finding.

    Notes:
    - For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    - The \"-k\" allows for specifying an arbitrary identifier, and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate audit events when adding and
deleting kernel modules.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    always,exit -F arch=b32 -S delete_module -k modules
    always,exit -F arch=b64 -S delete_module -k modules

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.

    To reload the rules file, issue the following command:

    $ sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag gid: 'V-238314'
  tag rid: 'SV-238314r654117_rule'
  tag stig_id: 'UBTU-20-010276'
  tag fix_id: 'F-41483r654116_fix'
  tag cci: ['CCI-000172']
  tag legacy: []
  tag nist: ['AU-12 c']
  #CHECK RULE, missing action
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

