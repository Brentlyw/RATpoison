# RATpoison
A quick way to reveal suspicious connections to your Windows machine.

# Features
- Traverses actively established connections with the host machine
- Filters out local IPs
- Checks parent process entropy (flags if largest executable section is > 7.0 entropy)
- Checks parent process signature (flags if no Authenticode signature available)
- Checks parent process arguments (flags if common malicious args are present)
- Checks parent process location on filesystem (flags if high-risk location)
- Established connection uses DDNS check (flags if known DDNS is present)
- Long connection time check (flags if established connection time is > 1hr)
- Non-standard port service usage check (flags if a standard svc is being used on non standard port)
- Sus port & High range port check (flags high risk ports and high range ports)
  *requires two of these flags being true to warrant suspicious report*

# Whats new?
- Version 1.1 - Introduces a complete revamp of UI and introduces more in depth checks, removes hostname whitelist.
- Version 1.0 - Initial release: Checks established connections hostname via whitelist.

# How to use?
- Install requirements.txt
- Run the python script
