control 'SV-238229' do
  title 'The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Verify the Ubuntu operating system, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.

Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf", and then ensure "ca" is enabled in "cert_policy" with the following command:

$ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca

cert_policy = ca,signature,ocsp_on;

If "cert_policy" is not set to "ca" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor.

Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf" and ensure "ca" is enabled in "cert_policy".

Add or update the "cert_policy" to ensure "ca" is enabled:

cert_policy = ca,signature,ocsp_on;

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000384-GPOS-00167', 'SRG-OS-000775-GPOS-00230']
  tag gid: 'V-238229'
  tag rid: 'SV-238229r1069088_rule'
  tag stig_id: 'UBTU-20-010060'
  tag fix_id: 'F-41398r653861_fix'
  tag cci: ['CCI-000185', 'CCI-001991', 'CCI-004909']
  tag nist: ['IA-5 (2) (a)', 'IA-5 (2) (b) (1)', 'IA-5 (2) (d)', 'SC-17 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    config_file = '/etc/sssd/sssd.conf'
    config_file_exists = file(config_file).exist?

    if config_file_exists
      describe ini(config_file) do
        its(['sssd', 'services']) { should match(/pam/) }
        its(['pam', 'pam_cert_auth']) { should cmp 'True' }
      end
      describe 'certificate_verification includes ca_cert in a domain section' do
        subject do
          ini(config_file).params.any? do |section, values|
            section.start_with?('domain/') &&
              values['certificate_verification'].to_s.include?('ca_cert')
          end
        end
        it { should be true }
      end
    else
      describe '/etc/sssd/sssd.conf exists' do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
