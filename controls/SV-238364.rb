control 'SV-238364' do
  title 'The Ubuntu operating system must use DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', 'Verify the directory containing the root certificates for the Ubuntu operating system contains certificate files for DoD PKI-established certificate authorities by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA".

If none is found, this is a finding.'
  desc 'fix', %q(Configure the Ubuntu operating system to use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.

Edit the "/etc/ca-certificates.conf" file, adding the character "!" to the beginning of all uncommented lines that do not start with the "!" character with the following command:

     $ sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf

Add at least one DoD certificate authority to the "/usr/local/share/ca-certificates" directory in the PEM format.

Update the "/etc/ssl/certs" directory with the following command:

     $ sudo update-ca-certificates)
  impact 0.5
  tag check_id: 'C-41574r880900_chk'
  tag severity: 'medium'
  tag gid: 'V-238364'
  tag rid: 'SV-238364r958868_rule'
  tag stig_id: 'UBTU-20-010443'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-41533r880901_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
  tag 'host'
  tag 'container'

  allowed_ca_fingerprints_regex = input('allowed_ca_fingerprints_regex')
  find_command = "
  for f in $(find -L /etc/ssl/certs -type f); do
    openssl x509 -sha256 -in $f -noout -fingerprint | cut -d= -f2 | tr -d ':' | egrep -vw '#{allowed_ca_fingerprints_regex}'
  done
  "
  describe command(find_command) do
    its('stdout') { should cmp '' }
  end
end
