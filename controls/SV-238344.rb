control 'SV-238344' do
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
  desc 'check', "Verify the system commands directories have mode 0755 or less permissive:

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
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the
following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin
/usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \\; "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000258-GPOS-00099 '
  tag gid: 'V-238344 '
  tag rid: 'SV-238344r654207_rule '
  tag stig_id: 'UBTU-20-010423 '
  tag fix_id: 'F-41513r654206_fix '
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
  tag 'host', 'container'

  system_commands = command('find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d').stdout.strip.split("\n").entries
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
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe "Number of directories that contain system commands found in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin or
      /usr/local/sbin, that are less permissive than 0755" do
        subject { valid_system_commands }
        its('count') { should eq 0 }
      end
  end
end
