# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal documentation fragments declaring what every module in this
collection supports.

The leading underscore on the file name is the declaration: these fragments are
private to the collection and may change in any release without a major version
bump. A module depends on one only by including it by FQCN.
"""

from __future__ import annotations


class ModuleDocFragment:
    # The bare options mapping lets a fragment carrying only attributes merge into a
    # module that declares options of its own.
    #
    # The support values have to live in attributes, because that is the only place
    # validate-modules reads them. A module whose check mode is incomplete overrides
    # check_mode with `support: partial` in its own DOCUMENTATION, and
    # validate-modules rejects that unless it names what the module does not do.
    CHECK_MODE_DIFF_MODE = r"""
options: {}
attributes:
  check_mode:
    description: >-
      The module honours check mode, reporting the changes it would make and
      writing nothing.
    support: full
  diff_mode:
    description: >-
      The module returns the state before and after each change, which Ansible
      renders as a diff.
    support: full
"""

    # The modules reach the Tailscale Admin API over HTTPS from the controller
    # rather than reaching the managed host, so both attributes are N/A rather
    # than full: the target's connection plugin and become settings have no
    # meaning for them.
    CONNECTION_DELEGATION = r"""
options: {}
attributes:
  connection:
    description: >-
      The module runs in the AnsibleModule process on the controller, so the
      target's connection plugin and become settings are not used.
    support: N/A
  delegation:
    description: >-
      Delegation does not apply, because the module neither runs on the managed
      host nor consumes the connection plugin. A playbook that still sets
      delegate_to has the module run on the delegate, where it reaches the
      Tailscale API over that host's network instead of the controller's.
    support: N/A
"""
