https://superuser.com/questions/715632/how-does-dig-trace-actually-work

dig +trace www.google.co.uk

* choose a random root server => 192.5.5.241
* send a non-recursive request to 192.5.5.241 for www.google.co.uk
* in the authority section, choose a random NS server for uk. domain => 195.66.240.130
* send a non-recursive request to 195.66.240.130 for www.google.co.uk
* in the authority section, choose a random NS server for google.co.uk. domain => 
