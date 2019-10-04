# **More Than A Crush ! (500 Pts)**

![TASK](https://i.ibb.co/VmMJsdj/Capture-d-cran-de-2019-10-04-15-50-23.jpg)

More Than A crush was a Forensics task from Securinets Integration Day CTF , we were given a .pcap file (wireshark capture) , after opening the .pcap file this is what we have found 

![wireshark](https://i.ibb.co/ck07Sgx/Capture-d-cran-de-2019-10-04-15-53-28.jpg)

it contained more than 2400 packets , so the first step i did was to inspect the http requests but unfortunately i found a **fake flag** and didn't work :'( The author is really making fun of us xD

![http](https://i.ibb.co/6nKx6SN/Capture-d-cran-de-2019-10-04-15-57-00.jpg)

So after inspecting the packets we noticed that there was some unusual traffic , over 350 ICMP packets were sent ! This is really unusual (until we are performing a DOS attack xd but this is not the case)

![icmp](https://i.ibb.co/pbWZf2G/Capture-d-cran-de-2019-10-04-16-03-32.jpg)

the key to to solve this task is to know that usually ICMP packets with the same source and Destination IP have a **unique ID ** so we can suppose that the solution has a relation with the ICMP id , after some enumeration you we can see that the IDs are in the range of printable chars () , Soo here is our supposition : Maybe the ID hold the Ascii code of each character of the flag ! Let's Try it :smiley: Scriptiing Time :grinning: 

I wrote this small script using the famous Scapy library in python for packet crafting (you can read about it [HERE](https://scapy.net/))

`#EXTRACT RAW FLAG`

`def extract_flag():`

    `flag=""`

    `packets=rdpcap("hard.pcap")`

    `for pckt in packets :`

        `if pckt.haslayer(scapy.all.ICMP) :`

            `if pckt[scapy.all.ICMP].type==0:`

                `try:`

                    `flag+=chr(pckt[scapy.all.ICMP].id)`

                `except ValueError:`

                    `continue    `

    `return flag            `


`#MAIN`

`raw_flag=extract_flag()    `

`print("[+]Found Raw Flaaaaaaag : "+raw_flag)`

This script read the pcap file and extract the id of ICMP packets type 0, just to mention that if you don't include the ICMP type test you will face some problems because of the 'Malformed Packets' that appear in the wireshark capture, in fact the ICMP have several types and here only the type 0 (Echo-Reply) have an ASCII code in their IDs . We run the script and **BINGO** we got this 

`Securinets{DASHDASH DOTDOT DASHDOTDOTDASH DOTDOT DASHDOT DASHDASHDOT DASHDOTDOTDOTDOTDASH DASHDASH DASHDASHDASH DOTDASHDOT DOTDOTDOT DOT DASHDOTDOTDOTDOTDASH DOTDASHDASH DOTDOT DASH DOTDOTDOTDOT DASHDOTDOTDOTDOTDASH DASHDOT DOT DASH DOTDASHDASH DASHDASHDASH DOTDASHDOT DASHDOTDASH}`

We can rapidly notice that these "Dash" and "DOT" are some Morse code so we add these two lines to our script in order to replace "DASH" ==>"-" and "DOT"==>"."

`#REPLACING DOT and DASH`

`flag=raw_flag.replace("DOT",".")`

`flag=flag.replace("DASH","-")`

`print("[+]Found PreeeFlaag "+flag)`

Now we got this 

`Securinets{-- .. -..- .. -. --. -....- -- --- .-. ... . -....- .-- .. - .... -....- -. . - .-- --- .-. -.-}`

And finally after decoding the morse code we find the flag 

**Securinets{MIXING-MORSE-WITH-NETWORK}**

I hope that you enjoyed this task and learned a lot from him don't hesitate to ask me if you faced any problems

