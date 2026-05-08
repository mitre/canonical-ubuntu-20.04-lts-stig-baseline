control 'SV-238350' do
  title 'The Ubuntu operating system library directories must be owned by root.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories "/lib", "/lib64", and "/usr/lib" are owned by root with the following command:

$ sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any system-wide library directory is returned, this is a finding.)
  desc 'fix', "Configure the library files and their respective parent directories to be protected from unauthorized access. Run the following command:

$ sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \\;"
  impact 0.5
  tag check_id: 'C-41560r654223_chk'
  tag severity: 'medium'
  tag gid: 'V-238350'
  tag rid: 'SV-238350r991560_rule'
  tag stig_id: 'UBTU-20-010429'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-41519r654224_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
