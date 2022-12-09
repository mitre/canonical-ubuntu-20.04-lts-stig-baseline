control 'SV-238216' do
  title "The Ubuntu operating system must configure the SSH daemon to use Message Authentication
Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the
unauthorized disclosure of information and/or detect changes to information during
transmission. "
  desc "Without cryptographic integrity protections, information can be altered by unauthorized
users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information
systems by an authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are
those activities conducted by individuals communicating through a network, either an
external network (e.g., the internet) or an internal network.

Local maintenance and
diagnostic activities are those activities carried out by individuals physically present
at the information system or information system component and not communicating across a
network connection.

Encrypting information for transmission protects information from
unauthorized disclosure and modification. Cryptographic mechanisms implemented to
protect information integrity include, for example, cryptographic hash functions which
have common application in digital signatures, checksums, and message authentication
codes.

 "
  desc 'check', "Verify the SSH daemon is configured to only use MACs that employ FIPS 140-2 approved ciphers
with the following command:

$ grep -ir macs /etc/ssh/sshd_config*

MACs
hmac-sha2-512,hmac-sha2-256

If any ciphers other than \"hmac-sha2-512\" or
\"hmac-sha2-256\" are listed, the order differs from the example above, or the returned line is
commented out, this is a finding.
If conflicting results are returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to allow the SSH daemon to only use MACs that employ FIPS
140-2 approved ciphers.

Add the following line (or modify the line to have the required
value) to the \"/etc/ssh/sshd_config\" file (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party vendor):

MACs
hmac-sha2-512,hmac-sha2-256

Restart the SSH daemon for the changes to take effect:

$
sudo systemctl reload sshd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000424-GPOS-00188 '
  tag satisfies: %w(SRG-OS-000424-GPOS-00188 SRG-OS-000250-GPOS-00093 SRG-OS-000393-GPOS-00173)
  tag gid: 'V-238216 '
  tag rid: 'SV-238216r860820_rule '
  tag stig_id: 'UBTU-20-010043 '
  tag fix_id: 'F-41385r653822_fix '
  tag cci: %w(CCI-001453 CCI-002421 CCI-002890)
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']
  tag 'host'

  if input('disable_fips')
    impact 0.0
    describe 'FIPS testing has been disabled' do
      skip 'This control has been set to Not Applicable, FIPS validation has been disabled with the `disable_fips` input'
    end
  elsif virtualization.system.eql?('docker')
    describe 'FIPS validation in a container must be reviewed manually' do
      skip 'FIPS validation in a container must be reviewed manually'
    end
  else
    @macs_array = inspec.sshd_config.params['macs']

    @macs_array = @macs_array.first.split(',') unless @macs_array.nil?

    describe @macs_array do
      it { should be_in %w(hmac-sha2-256 hmac-sha2-512) }
    end
  end
end
