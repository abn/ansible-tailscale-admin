---
    modules/          one file per module, flat. No nesting: a nested module
                       cannot be addressed by a short FQCN and ansible-lint fails it.
    module_utils/     code imported by modules on the target host. Everything here
                       runs under AnsiballZ, so it may use only the standard library
                       and ansible.module_utils.
    doc_fragments/    reusable documentation blocks, referenced by FQCN.
    lookup/           controller-side. May import the full ansible package.
    filter/           controller-side. May import the full ansible package.

The controller-side and target-side split is the important boundary. A lookup or
filter may use `requests`-era conveniences and read local files; a module may do
neither. Getting that wrong produces a module that works on the controller and
fails on the target.
