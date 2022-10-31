# encoding: UTF-8

control "SV-238252" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses 
of the su command. "
  desc "Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events 
relating to an incident or identify those responsible for one. 
 
Audit records can be 
generated from various components within the information system (e.g., module or policy 
filter). "
  desc "check", "Verify the Ubuntu operating system generates audit records upon successful/unsuccessful 
attempts to use the \"su\" command. 
 
Check the configured audit rules with the following 
commands: 
 
$ sudo auditctl -l | grep '/bin/su' 
 
-a always,exit -F path=/bin/su -F perm=x -F 
auid&gt;=1000 -F auid!=4294967295 -k privileged-priv_change 
 
If the command does not 
return lines that match the example or the lines are commented out, this is a finding. 
 
Note: 
The \"-k\" allows for specifying an arbitrary identifier, and the string after it does not need 
to match the example output above. "
  desc "fix", "Configure the Ubuntu operating system to generate audit records when 
successful/unsuccessful attempts to use the \"su\" command occur. 
 
Add or update the 
following rules in the \"/etc/audit/rules.d/stig.rules\" file: 
 
-a always,exit -F 
path=/bin/su -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-priv_change  
 

To reload the rules file, issue the following command: 
 
$ sudo augenrules --load "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000064-GPOS-00033 "
  tag gid: "V-238252 "
  tag rid: "SV-238252r653931_rule "
  tag stig_id: "UBTU-20-010136 "
  tag fix_id: "F-41421r653930_fix "
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

  @audit_file = '/bin/su'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end