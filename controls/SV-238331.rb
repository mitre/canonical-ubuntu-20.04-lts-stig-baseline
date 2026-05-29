control 'SV-238331' do
  title 'The Ubuntu operating system must automatically expire temporary accounts within 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.'
  desc 'check', 'Verify temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

     $ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure the operating system to expire temporary accounts after 72 hours with the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.3
  tag check_id: 'C-41541r902860_chk'
  tag severity: 'low'
  tag gid: 'V-238331'
  tag rid: 'SV-238331r958508_rule'
  tag stig_id: 'UBTU-20-010410'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-41500r902861_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
  tag 'host'
  tag 'container'

  describe 'Manual verification required' do
    skip 'Manually verify if emergency account must be created
      the system must terminate the account after a 72 hour time period.'
  end
end
