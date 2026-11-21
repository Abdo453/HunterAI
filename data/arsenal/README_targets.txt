category       installed  repo
------------------------------------------------------------------------------
wordlists      no         https://github.com/danielmiessler/SecLists.git
payloads       YES        https://github.com/swisskyrepo/PayloadsAllTheThings.git
nuclei         YES        https://github.com/projectdiscovery/nuclei-templates.git
fuzzdb         no         https://github.com/fuzzdb-project/fuzzdb.git
waf-bypass     YES        https://github.com/nemesida-waf/waf_bypass.git

usage:
    python scripts/arsenal_fetch.py pull <category>
    python scripts/arsenal_fetch.py pull all --shallow
    python scripts/arsenal_fetch.py clean <category>
