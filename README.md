# RATpoison
A quick way to reveal suspicious connections to your Windows machine.

# Features
- Traverses actively established connections with the host machine
- Filters out local IPs
- Checks parent process entropy 
- Checks parent process signature 
- Checks parent process arguments  
- Checks parent process location on filesystem  
- Established connection uses DDNS check 
- Long connection time check
- Non-standard port service usage check 
- Sus port & High range port check 
  *requires two of these flags being true to warrant suspicious report*

# Whats new?
- Version 1.1 - Introduces a complete revamp of UI and introduces more in depth checks, removes hostname whitelist.
- Version 1.0 - Initial release: Checks established connections hostname via whitelist.

# How to use?
- Install requirements.txt
- Run the python script
