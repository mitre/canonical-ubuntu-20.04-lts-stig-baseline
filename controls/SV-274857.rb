control 'SV-274857' do
  title 'Ubuntu 20.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command:

$ grep -i ldap_user_certificate /etc/sssd/sssd.conf
ldap_user_certificate=userCertificate;binary'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

ldap_user_certificate=userCertificate;binary'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-274857'
  tag rid: 'SV-274857r1101692_rule'
  tag stig_id: 'UBTU-20-010022'
  tag fix_id: 'F-78863r1101691_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  sssd_conf = input('sssd_conf_path')

  describe file(sssd_conf) do
    it { should exist }
  end

  describe 'SSSD PKI mapping setting' do
    subject { file(sssd_conf).content.to_s }

    it "includes 'ldap_user_certificate=userCertificate;binary'" do
      expected = /^\s*ldap_user_certificate\s*=\s*userCertificate;binary\s*$/m
      expect(subject).to match(expected), "Expected #{sssd_conf} to contain: ldap_user_certificate=userCertificate;binary"
    end
  end
end
