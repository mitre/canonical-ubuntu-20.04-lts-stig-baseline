# encoding: UTF-8

control "SV-238344" do
  title "The Ubuntu operating system must have directories that contain system commands set to a mode 
of 0755 or less permissive. "
  desc "Protecting audit information also includes identifying and protecting the tools used to 
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent 
unauthorized operation on audit information. 
 
Operating systems providing tools to 
interface with audit information will leverage user permissions and roles identifying the 
user accessing the tools and the corresponding rights the user has in order to make access 
decisions regarding the deletion of audit tools. 
 
Audit tools include, but are not limited 
to, vendor-provided and open source audit tools needed to successfully view and manipulate 
audit information system activity and records. Audit tools include custom queries and 
report generators. "
  desc "check", "Verify the system commands directories have mode 0755 or less permissive: 
 
/bin 
/sbin 

/usr/bin 
/usr/sbin 
/usr/local/bin 
/usr/local/sbin 
 
Check that the system command 
directories have mode 0755 or less permissive with the following command: 
 
$ find /bin /sbin 
/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" 
'{}' \\; 
 
If any directories are found to be group-writable or world-writable, this is a 
finding. "
  desc "fix", "Configure the system commands directories to be protected from unauthorized access. Run the 
following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin 
/usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \\; "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000258-GPOS-00099 "
  tag gid: "V-238344 "
  tag rid: "SV-238344r654207_rule "
  tag stig_id: "UBTU-20-010423 "
  tag fix_id: "F-41513r654206_fix "
  tag cci: ["CCI-001495"]
  tag nist: ["AU-9"]
end