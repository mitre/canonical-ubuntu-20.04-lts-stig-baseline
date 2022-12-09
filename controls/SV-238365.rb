control 'SV-238365' do
  title "Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized
modification of all information at rest. "
  desc "Operating systems handling data requiring \"data at rest\" protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of the
information at rest.

Selection of a cryptographic mechanism is based on the need to protect
the integrity of organizational information. The strength of the mechanism is commensurate
with the security category and/or classification of the information. Organizations have
the flexibility to either encrypt all information on storage devices (i.e., full disk
encryption) or encrypt specific data structures (e.g., files, records, or fields). "
  desc 'check', "If there is a documented and approved reason for not having data-at-rest encryption, this
requirement is Not Applicable.

Verify the Ubuntu operating system prevents unauthorized
disclosure or modification of all information requiring at-rest protection by using disk
encryption.

Determine the partition layout for the system with the following command:

$
sudo fdisk -l
(..)
Disk /dev/vda: 15 GiB, 16106127360 bytes, 31457280 sectors
Units:
sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size
(minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier:
83298450-B4E3-4B19-A9E4-7DF147A5FEFB

Device       Start      End  Sectors Size Type
/dev/vda1
2048     4095     2048   1M BIOS boot
/dev/vda2     4096  2101247  2097152   1G Linux filesystem
/dev/vda3
2101248 31455231 29353984  14G Linux filesystem
(...)

Verify that the system partitions
are all encrypted with the following command:

$ more /etc/crypttab

Every persistent
disk partition present must have an entry in the file.

If any partitions other than the boot
partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding. "
  desc 'fix', "To encrypt an entire partition, dedicate a partition for encryption in the partition layout.


Note: Encrypting a partition in an already-installed system is more difficult because it
will need to be resized and existing partitions changed. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000404-GPOS-00183 '
  tag gid: 'V-238365 '
  tag rid: 'SV-238365r853442_rule '
  tag stig_id: 'UBTU-20-010444 '
  tag fix_id: 'F-41534r654269_fix '
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
  tag 'host', 'container'

  describe 'Not Applicable' do
    skip 'Encryption of data at rest is handled by the IaaS'
  end
end
