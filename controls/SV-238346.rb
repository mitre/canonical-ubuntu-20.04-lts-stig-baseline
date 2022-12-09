control 'SV-238346' do
  title "The Ubuntu operating system must have directories that contain system commands group-owned
by root. "
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
  desc 'check', "Verify the system commands directories are group-owned by root:

/bin
/sbin
/usr/bin

/usr/sbin
/usr/local/bin
/usr/local/sbin

Run the check with the following command:


$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root
-type d -exec stat -c \"%n %G\" '{}' \\;

If any system commands directories are returned that are
not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a
finding. "
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the
following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin
/usr/local/sbin ! -group root -type d -exec chgrp root '{}' \\; "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000258-GPOS-00099 '
  tag gid: 'V-238346 '
  tag rid: 'SV-238346r654213_rule '
  tag stig_id: 'UBTU-20-010425 '
  tag fix_id: 'F-41515r654212_fix '
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
  tag 'host', 'container'
  
  system_commands = command('find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d').stdout.strip.split("\n").entries
  valid_system_commands = Set[]

  if system_commands.count > 0
    system_commands.each do |sys_cmd|
      if file(sys_cmd).exist?
        valid_system_commands = valid_system_commands << sys_cmd
      end
    end
  end

  if valid_system_commands.count > 0
    valid_system_commands.each do |val_sys_cmd|
      describe file(val_sys_cmd) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Number of directories that contain system commands found in /bin, /sbin, /usr/bin, /usr/sbin,
      /usr/local/bin or /usr/local/sbin, that are NOT group-owned by root" do
        subject { valid_system_commands }
        its('count') { should eq 0 }
      end
  end
end
