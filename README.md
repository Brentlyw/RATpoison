# RATpoison
A quick way to reveal suspicious connections to your Windows machine.

# Features
- Traverses actively established connections with the host machine
- Filters out local IPs
- Parent process entropy check (largest executable section)
- Parent process code signature check
- Parent process sus argument check
- Parent process sus filesystem location check
- Connection uses DDNS check
- Long connection time check (>1hr)
- Non-standard port service usage check
- Sus port & High range port check
  *requires two of these checks to flag, in order to mark suspicious.*

# Whats new?
- Version 1.1 - Introduces a complete revamp of UI and introduces more in depth checks, removes hostname whitelist.
- Version 1.0 - Initial release: Checks established connections hostname via whitelist.

# How to use?
- Install requirements.txt
- Run the python script
