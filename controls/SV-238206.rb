control 'SV-238206' do
  title "The Ubuntu operating system must ensure only users who need access to security functions are
part of sudo group. "
  desc "An isolation boundary provides access control and protects the integrity of the hardware,
software, and firmware that perform security functions.

Security functions are the
hardware, software, and/or firmware of the information system responsible for enforcing
the system security policy and supporting the isolation of code and data on which the
protection is based. Operating systems implement code separation (i.e., separation of
security functions from nonsecurity functions) in a number of ways, including through the
provision of security kernels via processor rings or processor modes. For non-kernel code,
security function isolation is often achieved through file system protections that serve to
protect the code on disk and address space protections that protect executing code.


Developers and implementers can increase the assurance in security functions by employing
well-defined security policy models; structured, disciplined, and rigorous hardware and
software development techniques; and sound system/security engineering principles.
Implementation may include isolation of memory space and libraries.

The Ubuntu operating
system restricts access to security functions through the use of access control mechanisms
and by implementing least privilege capabilities. "
  desc 'check', "Verify the sudo group has only members who should have access to security functions.

$ grep
sudo /etc/group

sudo:x:27:foo

If the sudo group contains users not needing access to
security functions, this is a finding. "
  desc 'fix', "Configure the sudo group with only members requiring access to security functions.

To
remove a user from the sudo group, run:

$ sudo gpasswd -d &lt;username&gt; sudo "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000134-GPOS-00068 '
  tag gid: 'V-238206 '
  tag rid: 'SV-238206r653793_rule '
  tag stig_id: 'UBTU-20-010012 '
  tag fix_id: 'F-41375r653792_fix '
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host', 'container'

  sudo_accounts = input('sudo_accounts')

  if sudo_accounts.count > 0
    sudo_accounts.each do |account|
      describe group('sudo') do
        its('members') { should include account }
      end
    end
  else
    describe.one do
      describe group('sudo') do
        its('members') { should be_nil }
      end
      describe group('sudo') do
        its('members') { should be_empty }
      end
    end
  end
end
