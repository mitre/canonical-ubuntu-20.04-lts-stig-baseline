# encoding: UTF-8

control "SV-238285" do
  title "The Ubuntu operating system must generate audit records for the use and modification of the 
tallylog file. "
  desc "Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events 
relating to an incident or identify those responsible for one. 
 
Audit records can be 
generated from various components within the information system (e.g., module or policy 
filter).

 "
  desc "check", "Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful 
modifications to the \"tallylog\" file. 
 
Check the currently configured audit rules with the 
following command: 
 
$ sudo auditctl -l | grep tallylog 
 
-w /var/log/tallylog -p wa -k 
logins 
 
If the command does not return a line that matches the example or the line is commented 
out, this is a finding. 
 
Note: The \"-k\" allows for specifying an arbitrary identifier, and 
the string after it does not need to match the example output above. "
  desc "fix", "Configure the audit system to generate an audit event for any successful/unsuccessful 
modifications to the \"tallylog\" file.  
 
Add or update the following rules in the 
\"/etc/audit/rules.d/stig.rules\" file: 
 
-w /var/log/tallylog -p wa -k logins 
   
To reload 
the rules file, issue the following command: 
 
$ sudo augenrules --load "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000064-GPOS-00033 "
  tag satisfies: ["SRG-OS-000064-GPOS-00033","SRG-OS-000470-GPOS-00214","SRG-OS-000473-GPOS-00218"]
  tag gid: "V-238285 "
  tag rid: "SV-238285r654030_rule "
  tag stig_id: "UBTU-20-010169 "
  tag fix_id: "F-41454r654029_fix "
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
end