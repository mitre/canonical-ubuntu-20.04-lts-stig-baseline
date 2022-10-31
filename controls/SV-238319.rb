# encoding: UTF-8

control "SV-238319" do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful 
attempts to use the kmod command. "
  desc "Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events 
relating to an incident or identify those responsible for one. 
 
Audit records can be 
generated from various components within the information system (e.g., module or policy 
filter). "
  desc "check", "Verify the Ubuntu operating system is configured to audit the execution of the module 
management program \"kmod\". 
 
Check the currently configured audit rules with the following 
command: 
 
$ sudo auditctl -l | grep kmod 
 
-w /bin/kmod -p x -k module 
 
If the command does not 
return a line, or the line is commented out, this is a finding. 
 
Note: The \"-k\" allows for 
specifying an arbitrary identifier, and the string after it does not need to match the example 
output above. "
  desc "fix", "Configure the Ubuntu operating system to audit the execution of the module management 
program \"kmod\". 
 
Add or update the following rule in the \"/etc/audit/rules.d/stig.rules\" 
file: 
 
-w /bin/kmod -p x -k modules 
  
To reload the rules file, issue the following command: 
 

$ sudo augenrules --load "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000477-GPOS-00222 "
  tag gid: "V-238319 "
  tag rid: "SV-238319r654132_rule "
  tag stig_id: "UBTU-20-010297 "
  tag fix_id: "F-41488r654131_fix "
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
end