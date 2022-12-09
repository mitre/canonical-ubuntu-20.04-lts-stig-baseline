control 'SV-238229' do
  title "The Ubuntu operating system, for PKI-based authentication, must validate certificates by
constructing a certification path (which includes status information) to an accepted trust
anchor. "
  desc "Without path validation, an informed trust decision by the relying party cannot be made when
presented with any certificate not already explicitly trusted.

A trust anchor is an
authoritative entity represented via a public key and associated data. It is used in the
context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When
there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can
be, for example, a Certification Authority (CA). A certification path starts with the
subject certificate and proceeds through a number of intermediate certificates up to a
trusted root certificate, typically issued by a trusted CA.

This requirement verifies
that a certification path to an accepted trust anchor is used for certificate validation and
that the path includes status information. Path validation is necessary for a relying party
to make an informed trust decision when presented with any certificate not already
explicitly trusted. Status information for certification paths includes certificate
revocation lists or online certificate status protocol responses. Validation of the
certificate status information is out of scope for this requirement. "
  desc 'check', "Verify the Ubuntu operating system, for PKI-based authentication, has valid certificates
by constructing a certification path to an accepted trust anchor.

Determine which pkcs11
module is being used via the \"use_pkcs11_module\" in \"/etc/pam_pkcs11/pam_pkcs11.conf\"
and then ensure \"ca\" is enabled in \"cert_policy\" with the following command:

$ sudo grep
use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc
{/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca

cert_policy =
ca,signature,ocsp_on;

If \"cert_policy\" is not set to \"ca\" or the line is commented out,
this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system, for PKI-based authentication, to validate
certificates by constructing a certification path to an accepted trust anchor.

Determine
which pkcs11 module is being used via the \"use_pkcs11_module\" in
\"/etc/pam_pkcs11/pam_pkcs11.conf\" and ensure \"ca\" is enabled in \"cert_policy\".

Add or
update the \"cert_policy\" to ensure \"ca\" is enabled:

cert_policy = ca,signature,ocsp_on;


If the system is missing an \"/etc/pam_pkcs11/\" directory and an
\"/etc/pam_pkcs11/pam_pkcs11.conf\", find an example to copy into place and modify
accordingly at
\"/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz\". "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000066-GPOS-00034 '
  tag gid: 'V-238229 '
  tag rid: 'SV-238229r653862_rule '
  tag stig_id: 'UBTU-20-010060 '
  tag fix_id: 'F-41398r653861_fix '
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?
    if config_file_exists
      describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
        its('use_pkcs11_module') { should_not be_nil }
        its('cert_policy') { should include 'ca' }
      end
    else
      describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
