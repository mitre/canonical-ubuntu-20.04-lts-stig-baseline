control 'SV-238217' do
  title 'The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.

By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.'
  desc 'check', %q(Verify the SSH daemon is configured to only implement FIPS-approved algorithms by running the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ciphers'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to allow the SSH daemon to only implement FIPS-approved algorithms.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-41427r951474_chk'
  tag severity: 'medium'
  tag gid: 'V-238217'
  tag rid: 'SV-238217r1117271_rule'
  tag stig_id: 'UBTU-20-010044'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag fix_id: 'F-41386r653825_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002421', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']
  tag 'host'

  if input('disable_fips')
    impact 0.0
    describe 'FIPS testing has been disabled' do
      skip 'This control has been set to Not Applicable, FIPS validation has been disabled with the `disable_fips` input'
    end
  elsif %w[docker podman kubepods lxc].include?(virtualization.system)
    describe 'FIPS validation in a container must be reviewed manually' do
      skip 'FIPS validation in a container must be reviewed manually'
    end
  else
    approved = input('approved_ciphers')
    ciphers = inspec.sshd_active_config.params['ciphers']
    ciphers = ciphers.first.split(',').map(&:strip) unless ciphers.nil?

    describe 'SSH ciphers' do
      it 'should contain only approved FIPS ciphers' do
        unapproved_ciphers = ciphers.nil? ? [] : (ciphers - approved)
        missing_approved_ciphers = ciphers.nil? ? approved : (approved - ciphers)

        expect(ciphers).to_not be_nil, 'Ciphers directive missing from sshd_config'
        expect(unapproved_ciphers).to eq([]), "Non-approved ciphers present (#{unapproved_ciphers.length}): #{unapproved_ciphers.join(', ')}"
        expect(missing_approved_ciphers).to eq([]), "Approved ciphers missing (#{missing_approved_ciphers.length}): #{missing_approved_ciphers.join(', ')}"
      end
    end
  end
end
