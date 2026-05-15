control 'SV-238347' do
  title 'The Ubuntu operating system library files must have mode 0755 or less permissive.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" have mode 0755 or less permissive.

Check that the systemwide shared library files have mode 0755 or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to have mode 0755 or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec chmod go-w {} +)
  impact 0.5
  tag check_id: 'C-41557r1101666_chk'
  tag severity: 'medium'
  tag gid: 'V-238347'
  tag rid: 'SV-238347r1106136_rule'
  tag stig_id: 'UBTU-20-010426'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-41516r1106135_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_files = if os.arch == 'x86_64'
                    command('find /lib /lib32 lib64 /usr/lib /usr/lib32 -perm /022 -type f').stdout.strip.split("\n").entries
                  else
                    command('find /lib /usr/lib /usr/lib32 /lib32 -perm /022 -type f').stdout.strip.split("\n").entries
                  end

  if library_files.any?
    library_files.each do |lib_file|
      describe file(lib_file) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are less permissive than 0755' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
