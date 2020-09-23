# Proof of Concept for BEAST (chosen-plaintext attack)

This proof of concept is focused on the cryptography behind the BEAST (Browser Exploit Against SSL/TLS) attack presented by Thai Duong and Juliano Rizzo on September 23, 2011. This a [chosen-plaintext attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) and this allow you to retrieve sensitives informations if the Transport Layer Security used is TLS1.0 or SSLv3.
The orginal proof of concept can be found here : [Here come the Ninjas](http://netifera.com/research/beast/beast_DRAFT_0621.pdf)

More Details about BEAST can be found [here](report.pdf)


### Demo

```
python2 beast.py 
```

We can also try with a custom cookie instead of hardcoded one, 
```
 python2 beast.py --cookie aNothEr5ecRetcOoKIE
```
