# Udergraduate Thesis/Project
This is my undergraduate project in which I did research and produced an essay and a python program. I touched on and incorporated many protocols and technologies including ip, dns, http, certificates etc.

### Thesis
This is not an academic paper but a very well written article documenting my research on the related topics and the python code I wrote. I talk about the key concepts, go through the software code and explain the design and workflow and showcase running the software with photos.

### software
I showcased usage of this software in detail with photos in the thesis. It is for linux platform but it can be easily adjusted for windows.
To use the software we run it on the target system with priviledged access and give it a website name as a command-line argument. It manipulates dns records system-wide for target domain and points it to the attacker server(here local server by software itself). It also generates corresponding self-signed certificates to bypass ssl traffic.
  Now all traffic rogue server which we control. We have effectively compromise both confidentiallity and integrity of the system. We can take a passive approach and just sniff the traffic looking for passwords, etc. Or we can combine this to perform other attack by running arbitrary code on behalf of target domain on user's browser which allows us to do a handful of attacks including phishing. A simple scenario which is showcased in the thesis is to integrate this with famous `beef framework` and hook the user's browser to beef framework by injecting beef created url to user's receiving traffic which enables us to further execute hundereds of beef scripts.
