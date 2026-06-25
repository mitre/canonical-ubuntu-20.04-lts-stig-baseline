ansible-role-ubuntu-hardened
============================

This role prepares an Ubuntu 20.04 host for hardened baseline validation by applying supplemental hardening tasks used by the test harness. It is intended for systems that should resemble a STIG-hardened target rather than a plain vanilla image.

Requirements
------------

Ansible must be able to connect to the target with privileges sufficient to apply system configuration changes and install or update packages from the configured apt repositories.

Role Variables
--------------

This role does not currently define any tunable variables.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      become: true
      roles:
         - ansible-role-ubuntu-hardened

License
-------

Apache-2.0

Author Information
------------------

See the repository maintainers.
