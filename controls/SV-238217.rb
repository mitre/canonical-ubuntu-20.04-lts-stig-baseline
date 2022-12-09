control 'SV-238217' do
  title "The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers
to prevent the unauthorized disclosure of information and/or detect changes to information
during transmission. "
  desc "Without cryptographic integrity protections, information can be altered by unauthorized
users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information
systems by an authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are
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

By specifying a cipher list with the order of ciphers being in a \"strongest to
weakest\" orientation, the system will automatically attempt to use the strongest cipher for
securing SSH connections.

 "
  desc 'check', "Verify the SSH daemon is configured to only implement FIPS-approved algorithms by running
the following command:

$ grep -r 'Ciphers' /etc/ssh/sshd_config*

Ciphers
aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than \"aes256-ctr\",
\"aes192-ctr\", or \"aes128-ctr\" are listed, the order differs from the example above, the
\"Ciphers\" keyword is missing, or the returned line is commented out, this is a finding.
If
conflicting results are returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to allow the SSH daemon to only implement
FIPS-approved algorithms.

Add the following line (or modify the line to have the required
value) to the \"/etc/ssh/sshd_config\" file (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party vendor):


Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon for the changes to
take effect:

$ sudo systemctl restart sshd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000424-GPOS-00188 '
  tag satisfies: %w(SRG-OS-000424-GPOS-00188 SRG-OS-000033-GPOS-00014 SRG-OS-000394-GPOS-00174)
  tag gid: 'V-238217 '
  tag rid: 'SV-238217r860821_rule '
  tag stig_id: 'UBTU-20-010044 '
  tag fix_id: 'F-41386r653825_fix '
  tag cci: %w(CCI-000068 CCI-002421 CCI-003123)
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
    @ciphers_array = inspec.sshd_config.params['ciphers']

    @ciphers_array = @ciphers_array.first.split(',') unless @ciphers_array.nil?

    describe @ciphers_array do
      it { should be_in %w(aes256-ctr aes192-ctr aes128-ctr) }
    end
  end
end
