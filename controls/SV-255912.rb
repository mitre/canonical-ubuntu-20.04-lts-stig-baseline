control 'SV-255912' do
  title 'The Ubuntu operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', %q(Verify the SSH server is configured to use only FIPS-validated key exchange algorithms:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*kexalgorithms'

KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

If "KexAlgorithms" is not configured, is commented out, or does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, this is a finding.)
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/ssh/sshd_config":

     KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the "sshd" service for changes to take effect:

     $ sudo systemctl restart sshd'
  impact 0.5
  tag check_id: 'C-59589r951476_chk'
  tag severity: 'medium'
  tag gid: 'V-255912'
  tag rid: 'SV-255912r991554_rule'
  tag stig_id: 'UBTU-20-010045'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-59532r880904_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || package('openssh-server').installed?
  }

  expected_kex = input('expected_kex')

  sshd_t_output = command('/usr/sbin/sshd -T 2>/dev/null').stdout
  kex_line = sshd_t_output.lines.find { |l| l.start_with?('kexalgorithms ') }
  actual_kex = kex_line.nil? ? [] : kex_line.split(/\s+/, 2)[1].to_s.strip.split(',')

  describe 'Effective SSHD KexAlgorithms' do
    subject { actual_kex }
    it 'is set and exactly matches the required FIPS-validated algorithms in order' do
      expect(subject).to eq(expected_kex), <<~MSG.chomp
        Expected KexAlgorithms to be exactly (in order):
          - #{expected_kex.join("\n  - ")}
        Actual:
          - #{actual_kex.join("\n  - ")}
      MSG
    end
  end
end
