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
 
