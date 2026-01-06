**Finding Subdomains**:  
**assetfinder**: go get -u github.com/tomnomnom/assetfinder  
assetfinder soda.com  
assetfinder --subs-only soda.com  

**Amass**: by OWASP, takes time,  go get -v -u github.com/OWASP/Amass/v3/...  
amass enum -d soda.com  

**Finding alive domains with Httprobe**:  
go get -u github.com/tomnomnom/httprobe  
cat domains.txt | httprobe   //send http and https req  

**Screenshotting websites with GoWitness**:  https://github.com/sensepost/gowitness  







