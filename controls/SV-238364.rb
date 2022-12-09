control 'SV-238364' do
  title "The Ubuntu operating system must only allow the use of DoD PKI-established certificate
authorities for verification of the establishment of protected sessions. "
  desc "Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by
organizations or individuals that seek to compromise DoD systems or by organizations with
insufficient security controls. If the CA used for verifying the certificate is not a
DoD-approved CA, trust of this CA has not been established.

The DoD will only accept
PKI-certificates obtained from a DoD-approved internal or external certificate
authority. Reliance on CAs for the establishment of secure sessions includes, for example,
the use of SSL/TLS certificates. "
  desc 'check', "Verify the directory containing the root certificates for the Ubuntu operating system
(/etc/ssl/certs) only contains certificate files for DoD PKI-established certificate
authorities.

Determine if \"/etc/ssl/certs\" only contains certificate files whose
sha256 fingerprint match the fingerprint of DoD PKI-established certificate authorities
with the following command:

$ for f in $(realpath /etc/ssl/certs/*); do openssl x509
-sha256 -in $f -noout -fingerprint | cut -d= -f2 | tr -d ':' | egrep -vw '(9676F287356C89A12683D65234098CB77C4F1C18F23C0E541DE0E196725B7EBE|B107B33F453E5510F68E513110C6F6944BACC263DF0137F821C1B3C2F8F863D2|559A5189452B13F8233F0022363C06F26E3C517C1D4B77445035959DF3244F74|1F4EDE9DC2A241F6521BF518424ACD49EBE84420E69DAF5BAC57AF1F8EE294A9)';
done

If any entry is found, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to only allow the use of DoD PKI-established
certificate authorities for verification of the establishment of protected sessions.


Edit the \"/etc/ca-certificates.conf\" file, adding the character \"!\" to the beginning of
all uncommented lines that do not start with the \"!\" character with the following command:

$
sudo sed -i -E 's/^([^!#]+)/!\\1/' /etc/ca-certificates.conf

Add at least one DoD
certificate authority to the \"/usr/local/share/ca-certificates\" directory in the PEM
format.

Update the \"/etc/ssl/certs\" directory with the following command:

$ sudo
update-ca-certificates "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000403-GPOS-00182 '
  tag gid: 'V-238364 '
  tag rid: 'SV-238364r860824_rule '
  tag stig_id: 'UBTU-20-010443 '
  tag fix_id: 'F-41533r860823_fix '
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
  tag 'host', 'container'

  allowed_ca_fingerprints_regex = input('allowed_ca_fingerprints_regex')
  find_command = ''"
  for f in $(find -L /etc/ssl/certs -type f); do
    openssl x509 -sha256 -in $f -noout -fingerprint | cut -d= -f2 | tr -d ':' | egrep -vw '#{allowed_ca_fingerprints_regex}'
  done
  "''
  describe command(find_command) do
    its('stdout') { should cmp '' }
  end
end
