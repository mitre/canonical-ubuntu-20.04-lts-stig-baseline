# encoding: UTF-8

control "SV-238345" do
  title "The Ubuntu operating system must have directories that contain system commands owned by 
root. "
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
  desc "check", "Verify the system commands directories are owned by root: 
 
/bin 
/sbin 
/usr/bin 

/usr/sbin 
/usr/local/bin 
/usr/local/sbin 
 
Use the following command for the check: 
 

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root 
-type d -exec stat -c \"%n %U\" '{}' \\; 
 
If any system commands directories are returned, this is 
a finding. "
  desc "fix", "Configure the system commands directories to be protected from unauthorized access. Run the 
following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin 
/usr/local/sbin ! -user root -type d -exec chown root '{}' \\; "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000258-GPOS-00099 "
  tag gid: "V-238345 "
  tag rid: "SV-238345r654210_rule "
  tag stig_id: "UBTU-20-010424 "
  tag fix_id: "F-41514r654209_fix "
  tag cci: ["CCI-001495"]
  tag nist: ["AU-9"]
end