# antiscan-antienumeration

## code1.py : 
code liyban mlih mais lzm nsagmoh , kiydetecti scan , ichd ip oy93d iralentiha bch mtrj3ch reponse  , wsmha tarpit

## Avec netsh 
 ybloki ga3 les scan omy5alikch tscani mais i5alik dir ping , kan code hayl hata f9t bali rah y5dm b netsh okichft wchno netsh , kan idirli des rules fal firewall pourtant firewall ta3i mdesactivi , donc nrmlment m3ndha hata fayda hadi ligne prcq mkch firewall ,so rj3thom commentaire o3awdt siyit , t5sr chwiya code , donc capable meme lokan firewall mdesactivi , netsh 3ndo chemin y9dr y5dm bfirewall oycriyi des rules ..  

## Sans Netsh
t9dr tpingi oga3 les ports litscanihom sC sV sS -p 1-1000...   irj3lk klch filtered


## Sans Netsh V2 
ki3awdt siyit Sans netsh l9ito ymchi 5trat o 5atrat mymchich , capable nkon testito mor ta3 avec netsh osauvegarda les rules so drt hada msagm 3la sansnetsh nrml



## Sans NetshV3

hada ymchi bien , irj3lk scan filtered wy5alik tpingi o laffichage ta3o chaba 3la les versions l9dm ...  , kyn prblm wahd cest que mindak raho yablokili adresse mn3rfhach capable t3 routeur wla jcp , so lzm nsgmo code bch myblokich hado les adresses ; hahi image 3la sansnetshV3

(update) f9t bali lokan tlanci serveur fkch port kima 7000  , t9dr taccedilo blocalhost mais lokan tlanci code V3 , mtwalich t9dr taccedilo blocalhost , dok hada prblm lzm ytsgm tan
haho code bch tlanci serveur f 7000

powershell -Command "Start-Process -NoNewWindow -FilePath 'cmd' -ArgumentList '/c python -m http.server 7000'"

![Screenshot 2024-12-16 205709](https://github.com/user-attachments/assets/45516dc4-b2ba-40f7-9832-c41252ba4380)




## InterfaceV1
hello hello xd,  
rani zdt dossier interfaceV1 , nrmlment ymchi klch (t9dr dir internet , t9dr td5l lalport litftho kima 7000 ..., my9droch yaccidiwlo mn ghir ida nta t5alihom ...)  rayhin t3rfo ga3 hado kitsiyiw app , tl3o les deux fichiers limada5l dossier + mtbdlolhomch asm bch sur ymchi XD 
hahi image t3 interface m3a exemple t3 adresse maditlha port o adresse maditlha port whdo5r wmchaw , dok wch 93d, nsiyiw nl9aw kch commande lit9dr tscanni wajib reponse wnzido nchofo les types lina9sina, otani nchofo ida n5aliw affichage ta3 paquet wla nbadloh xd

![image](https://github.com/user-attachments/assets/fb2beb4d-cd0a-42e5-a361-bfe018326f95)



## InterfaceV2
ameliorit InterfaceV1  , raho idetecti les scans tcp udp sctp ssdp , fal V1 kan ghir tcp   ;; fhadi verion t9dr taccedi lalport lithalo ip:port    mais mawalatch kyn internet fhadi version :)) 
