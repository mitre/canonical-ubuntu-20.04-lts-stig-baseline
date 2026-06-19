control 'SV-278950' do
  title 'Ubuntu 20.04 LTS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Ubuntu 20.04 has reached the end of its standard support period and must be removed from the enclave network or upgraded to a supported version.

Standard support ended on 31 May 2025, meaning the end of free security updates and bug fixes.

Extended Security Maintenance (available with an UbuntuPro subscription) will expire May 2030.

Legacy add-on coverage will further extend security updates through May 2032.'
  desc 'check', 'Verify the version of Ubuntu 20.04 LTS is vendor supported with the following command:

$ grep DISTRIB_DESCRIPTION /etc/lsb-release
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"

If the installed version of Ubuntu 20.04 LTS is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of Ubuntu 20.04 LTS.'
  impact 0.7
  tag check_id: 'C-83484r1135396_chk'
  tag severity: 'high'
  tag gid: 'V-278950'
  tag rid: 'SV-278950r1135398_rule'
  tag stig_id: 'UBTU-20-010001'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-83389r1135397_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  lsb = parse_config_file('/etc/lsb-release')

  describe 'Ubuntu release description' do
    subject { lsb['DISTRIB_DESCRIPTION'] || '' }
    it { should match(/Ubuntu\s+20\.04(?:\.\d+)?\s+LTS/i) }
  end

  # Lifecycle windows derived from STIG narrative
  esm_support_eol = Time.new(2030, 5, 31, 23, 59, 59, '+00:00')
  now = Time.now.utc

  if now <= esm_support_eol
    # Within ESM window; verify Ubuntu Pro subscription status
    pro_status = command('pro status')

    if pro_status.exit_status != 0 || pro_status.stdout.strip.empty?
      describe 'Ubuntu Pro tooling unavailable' do
        skip 'Ubuntu Pro tooling not available; manual verification of ESM subscription status is required.'
      end
    else
      describe.one do
        describe 'Ubuntu Pro attached' do
          subject { pro_status.stdout }
          it { should match(/attached/i) }
          it { should_not match(/not\s+attached/i) }
        end

        describe 'ESM services enabled' do
          subject { pro_status.stdout }
          it { should match(/(?mi)\besm-(apps|infra)\b.*\benabled\b/) }
        end
      end
    end
  else
    # Beyond ESM end-of-life; release is no longer vendor supported
    describe 'Ubuntu 20.04 LTS ESM end-of-life status' do
      it 'is within vendor support lifecycle' do
        expect(now <= esm_support_eol).to be true, "Vendor support for Ubuntu 20.04 LTS ended on #{esm_support_eol.utc.strftime('%Y-%m-%d')}; current date: #{now.utc.strftime('%Y-%m-%d')}"
      end
    end
  end
end
