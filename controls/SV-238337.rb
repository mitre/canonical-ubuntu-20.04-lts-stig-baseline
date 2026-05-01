control 'SV-238337' do
  title 'The Ubuntu operating system must generate error messages that provide information
necessary for corrective actions without revealing information that could be exploited by
adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and organizations must carefully consider the content and structure of error messages. 
 
The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, Social Security numbers, and credit card numbers.

The /var/log/btmp, /var/log/wtmp, and /var/log/lastlog files have group write and global read permissions to allow for the lastlog function to perform. Limiting the permissions beyond this configuration will result in the failure of functions that rely on the lastlog database.'
  desc 'check', %q(Verify the Ubuntu operating system has all system log files under the "/var/log" directory with a permission set to "640" or less permissive by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If the command displays any output, this is a finding.

Note: If output regarding history.log or eipp.log.xz is displayed, this is not a finding.)
  desc 'fix', %q(Configure the Ubuntu operating system to set permissions of all log files under the "/var/log" directory to "640" or more restricted by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag gid: 'V-238337'
  tag rid: 'SV-238337r1134791_rule'
  tag stig_id: 'UBTU-20-010416'
  tag fix_id: 'F-41506r880875_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
  tag 'host'
  tag 'container'

  log_files = command('find /var/log -perm /137 -type f -exec stat -c "%n %a" {} \;').stdout.strip.split("\n").entries

  describe 'Number of log files found with a permission NOT set to 640' do
    subject { log_files }
    its('count') { should eq 0 }
  end
end
