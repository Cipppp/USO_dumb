## Sistemul de fisiere

Link simbolic

    ln -s file1 file2 = symbolic link

Afiseaza dimensiunea totala de pe disk a unui folder

    du -hs folder_name

Schimbare owner fisier

    sudo chown andrei only_andrei.txt

Drepturi de scriere si citire pentru vavle, iar restul doar drepturi de scriere.

    sudo chown valve shooters
    sudo chmod 602 shooters

Verifica daca utilitarul este instalat sau nu

    apt show cowsay

Afiseaza toti utilizatorii din sistem

    less /etc/passwd | cut -d ':' -f1

Afiseaza suma tuturor identificatorilor utilizatorilor de pe sistem.

    cat /etc/passwd | cut -d ":" -f 3 | sum

Afisati doar numele utilizatorilor care au ca shell implicit "/usr/sbin/nologin".

    cat /etc/passwd | grep /usr/sbin/nologin | awk -F ':' '{print $1}'

La rularea comenzii "sl" sa ruleze comanda "ls -alR".

    alias sl="ls -alR"

Alias numit "binaries" care afiseaza continutul variabilei de mediu "PATH".

    alias binaries="echo $PATH"

La rularea comenzii "superlist" sa fie afisat continutul directorului curent cu dimensiunea fisierelor in format human-readable.

    alias superlist="du -hs ."

Modificarile necesare astfel incat comanda ”la“ sa nu mai functioneze.

    unalias la

Afiseaza locatia utilitarului "cowsay" in sistem si care instaleaza utilitarul in cazul in care acesta nu exista.

    which cowsay || sudo apt-get install cowsay

Afiseaza sistemele de fisiere de pe sistem care sunt montate read-only.

    lsblk | grep " 1 "

Afiseaza liniile cu numar par din fisierul ”users.csv“.

    sed -n 2-2p users.csv

sau

    awk 'NR%2==0' users.csv

Ruleaza comanda ”echo "I am $USER, with uid $UID"“ de pe alt utilizator, fara a va a fi autentificat in mod interactiv ca acesta.

    sudo -H -u IronMan bash -c 'echo "I am $USER, with uid $UID"'

## Cautare

Cauta dupa dimensiunea fisierelor

    find /path -size +10M

Afiseaza toate fisierele obisnuite din /etc

    find /etc -maxdepth 1 -type f -ls | tr -s " " | cut -d " " -f12

Afisarea tuturor fisierele obisnuite (nu si directoarele) din radacina directorlui "/etc".

    ls -p /etc | grep -v /

Afisati toate fisierele ale caror nume contine sirul de caractere .log din ierarhia de fisiere "/var/log" si care au permisiunile rw- r-- ---.

    sudo find /var/log -type f -name "*.log" -perm 640

Afiseaza numarul utilizatorilor de pe sistem care au directorul home in cadrul ierarhiei de fisiere "/var".

    cat /etc/passwd | grep /var/ | wc -l

Afiseaza doar numele fiecarui utilizator care are configurat ca shell implicit executabilul ”/bin/false“.

    cat /etc/passwd | grep /bin/false | awk -F ":" '{print $1}'

Afiseaza numele si directorul home pentru fiecare utilizator al carui director "home" se afla in cadrul ierarhiei de fisiere "/home".

    cat /etc/passwd | grep "home" | awk -F '{print $1":"$6}'

Sterge toate fisierele care contin caracterul "t" in denumire din cadrul directorlui "Vegetables".

    find . -type f -name "*t*" -exec rm -rf {} \;

Afiseaza toate fisierele cu extensia ".ko" care se afla in ierarhia de fisiere "/lib" si au dimensiunea mai mare de 1 M.

    find /lib/ -type f -name \*.ko - size +1M

## Arhivare, comprimare

Creare arhiva

    tar -cvf archive_name.tar folder_to_compress/
    tar -zcvf archive_name.tar.gz folder_to_compress/ (pentru gz)

Dezarhivare arhiva

    tar -xvf archive_name.tar
    tar -zxvf archive_name.tar.gz (pentru gz)

Creeaza o arhiva cu parola care cuprinde continutul directorului "/home/student".

    zip -p parola -r arhiva4a.zip /home/student

## Procese, semnale

Informatii despre memoria totala

    free

Afiseaza doar userul, comanda, pid, ppid din procese ale utilizatorului avahi si syslog.

    ps -eo user,cmd,pid,ppid | egrep "^(avahi|syslog)"

Afiseaza toti utilizatorii care au procese active
( uniq are nevoie de sort in fata )

    ps aux | awk '{print $1}' | sort | uniq| grep -v USER

Afiseaza primele 10 procese ordonate dupa durata de timp de cand acestea au pornit,PID-ul, PPID-ul, utilizatorul si durata respectiva.

    ps xao pid,ppid,lstart,user --sort=lstart | head -n 10

Afiseaza toate serviciile pornite pe sistem.

    systemctl list-units --type service --state running

Afiseaza in ordine alfabetica utilizatorii din sistem care au procese pornite.

    ps aux | awk '{print $1}' | sort | uniq| grep -v USER

Afiseaza PID-ul, PPID-ul, utlizatorul, comanda cu are a fost creat si procentul de memorie pe care il consuma pentru primele 10 procese sortate descrescator dupa procentul de memorie.

    ps xao pid,ppid,user,comm,%mem | sort -rn -k 4 | head -n 10

Afiseaza pentru toate procesele din sistem doar PID-ul, utilizatorul care le-a creat si comanda folosita.

    ps aux | awk '{print $2" "$1" "$11}'

Afiseaza toate procesele de tip daemon din sistem

    ps -eo 'tty,pid,comm' | grep ^?

Afiseaza suma PID-urilor tuturor proceselor din sistem.

    ps aux | awk '{print $2}' | tail -n +2 | paste -s -d + - | bc

Pentru fiecare proces afisati PID-ul, PPID-ul, comanda si memoria utilizata.

    ps -efj | awk '{print $1" "$2" "$3" "$10}' | grep root | head -n -1

Afiseaza utilizatorii din sistem care au procese pornite. Fiecare nume de utilizator va fi afisat o singura data.

    ps aux | awk '{print $1}' | tail -n +2 | sort | uniq

Afiseaza arhitectura procesorului si dimensiunea memorie cache de nivel 2 folosind un oneliner.

    lscpu | grep Arhitecture ; less /proc/cpuinfo | grep "cache size" | uniq

Afiseaza doar cata memorie este folosita pe sistem in format human-readable.

    free -m | grep Mem | awk '{print $3}'

sau

    sudo df -H | awk '{print $3}'

Afiseaza memoria disponibila de pe masina de lucru in format human-readable.

    df -H | awk '{print $4}' | tail -n +4 | head -n 1

Afisare doar numele fiecarui serviciu din sistem.

    cat /etc/passwd | awk '{print $5}'

Afiseaza modelul procesorului, numarul de nuclee si flag-urile active ale procesorului.

    lscpu | grep "Model name" ; lscpu | head -n 5 | tail -n 1 ; lscpu | tail -n 1

Montati discul si afisati continutul fisierului "file" aflat in cadrul disclui "data".

    wget elf.cs.pub.ro/uso/res/final/31-jan-data
    sudo mkdir /mnt/drive_uso
    sudo mount data /mnt/mydrive
    cd /mnt/mydrive
    cat file

Adaugati un fisier denumit "task5" care sa contina numele vostru in discul montat anterior.

    cd ~
    echo "Nume_Intreg" > task5
    sudo mv task5 /mnt/mydrive
    cd /mnt/mydrive - Dovada_1

Opriti serviciul ”openvpn“.

    sudo systemctl stop openvpn

## Servicii retea

Afiseaza toate interfetele de retea si adresele lor ip

    ip address show

Conectare remote la host cu contul user

    ssh user@host

Conectare remote pe portul port_number

    ssh -p port_number@host

Generare cheii de autentificare

    ssh-keygen

Instalarea cheii publice pe masina remote

    ssh-copy-id

Afisati gateway-ul implicit configurat pe sistem.

    route | grep default | awk '{print $2}'

sau

    ip route show

Afiseaza doar adresa IPv4 a unui domeniu primit ca argument in linia de comanda.

    ip address show ens3 | grep "inet " | awk '{print $2}'

Afiseaza adresa IP publica a sistemului curent.

    dig +short myip.opendns.com @resolver1.opendns.com

Afiseaza adresa IP care corespunde domeniului "uso.cs.pub.ro".

    host uso.cs.pub.ro | awk '{print $4}' sau cu ding

Modificarile necesare astfel incat statia "red" sa aiba conectivitate la internet.

    sudo dhclient

Scrieti adresele IPv4 de pe toate interfetele de retea ale sistemului.

    ifconfig -a | grep "inet " | awk {'print $2'} > adrese.txt

Afiseaza porturile de tip TCP care asculta pe masina de lucru.

    sudo netstat -plnt

## Filtre text

Sorteaza in functie de coloana a 3-a

    sort -k 3 file

Inlocuiti toate aparitiile caracterului ”,“ din fisierul ”oracol.csv“ cu caracterul tab.

    sed -i 's/,/\'$'\t/g' oracol.csv

Inlocuieste a-z cu A-Z

    cat fisier | tr “[a-z]” “[A-Z]”

Creeaza o parola cu litere mici/mari si doar numere impare

    tr -dc '[a-z][a-z]13579' < /dev/urandom | fold -w 32 | head -n 1

Genereaza o parola de 32 caractere alfanumerice aleatoare si nu contine cifre pare.

    tr -dc '[a-z][a-z]13579' < /dev/urandom | fold -w 32 | head -n 1

Genreaza 42 de parole de 10 caractere care contin caractere printabile, mai putin litere.

    tr -dc '0-9!"#$%&'\''()\*+,-./:;<=>?@[\]^\_`{|}~' < /dev/urandom | fold -w 10 | head -n 42

Genereaza o parola de 24 de caractere ce contine doar litere, mai putin "b", "h" si "x" si cel putin o majuscula.

    pwgen -c -0 -remove-chars=bhx 24 | head -n 1

Creaza un fisier cu numele fisier.txt cu data random de marime 5MB

    dd if=/dev/urandom of=fisier.txt bs=5MB count=1

Creati fisier-ul "filezero" de dimensiunea 100 M care contine octeti de zero.

    dd if=/dev/zero of=fisier.txt bs=100MB count=1

Sortare descrescatore dupa al treilea camp al adresei IP.

    sort -t . -k 3,3n -k 4,4n adrese.txt (fisier cu adrese IP)

Generare fisier care contine linia "I can do this all day" de 1337 ori.

    yes "I can do this all day" | head -n 1337 > leet.txt
    cat leet.txt - Dovada1

# Creare si modificare conturi utilizator

Creare utilizator

    sudo useradd user_name

Creare grup

    sudo groupadd group_name

Modificare parola

    sudo passwd user_name

Stergere utilizator

    sudo deluser user_name

Adaugare utilizator in grup

    usermod -aG group_name user_name

Modificati directorul home al utilizatorului

    sudo usermod -d /home/zlatko luther
    cat /etc/passwd <-- dovada

Adauga in sistem utilizatorul "grajdar" cu directorul home "/home/spatemap1".

    sudo useradd -d /home/spatemap1 grajdar

Adauga in sistem utilizatorul "ana" cu shell-ul implicit "/bin/nologin".

    sudo useradd -s /bin/nologin

Modificarile necesare astfel incat utilizatorul "grajdar" sa nu se poata autentifica in sistem.

    sudo chsh -s /bin/false grajdar

sau

    sudo chsh -s /sbin/nologin metahype
    cat /etc/passwd - Dovada

Creati utilizatorul "metahype" cu grupul default "meta" astfel incat acesta sa nu aiba director home asociat.

    sudo groupadd meta
    sudo useradd -M metahype -g meta
    cat /etc/passwd - Dovada

## Securitate

Decriptare fisier

    openssl aes-256-cbc -d -in encrypted_file -out decrypted_file -pass pass:"uso_rullz"

Criptati textul "Good luck, student!" folosind algoritmul de criptare DES CBC si parola "final-exam".

    echo "Good luck, student!" > plaintext.txt

    openssl des-cbc -in plaintext.txt -out criptat.txt -pass pass:"final-exam"

    openssl des-cbc -d -in criptat.txt -out decriptat.txt -pass pass:"final-exam"

Cripteaza fisierul ”task4c.txt“ folosind algoritmul de criptare Camellia cu lungimea cheii de 192 biti folosind modul ECB. Parola de criptare este ”USO“. Fisierul criptat se va numi ”task4c.enc“.

    openssl camellia-192-ecb -in task4c.txt -out task4c.enc -pass pass:"USO"
    cat task4.enc - Dovada_1
    openssl camellia-192-ecb -d -in task4c.enc -out task4c.dec -pass pass:"USO" - Dovada_2

## Scripts

**1.** Script care primeste ca parametru calea catre un director si creeaza acel director. Daca directorul deja exista, se va afisa mesajul "Directory already exists".

    nano 4.sh
    chmod +x 4.sh

Continut script:

    #!/bin/bash
    DIR=$1

    if [ -d "$DIR" ]; then
        ## Take action if $DIR exists.
        echo "Directory already exists"
    else
        mkdir $DIR
        echo "Directory made successfully"
    fi

**2.** Script care primeste ca argument o adresa si afiseaza adresa IP asociata acesteia. Script-ul va intoarce codul de eroare 1 daca va primi mai mult sau mai putin de un argument.

    nano 4a.sh
    chmod +x 4a.sh

Continut script:

    #!/bin/bash
    address=$1

    if [ "$##" -ne 1 ]; then
        echo "Illegal number of parameters"
    else
        dig +short $1
    fi

**3.** Script care aplica algoritmul de encodare base64 asupra fiecarei linii a fisierului ”to_encode.txt“ din arhiva de la subpunctul anterior.

    #!/bin/bash
    nr=$(cat ~/to_encode.txt | wc -l)
    for i in $(seq 1 $nr);
    do
        text=$(cat ~/to_encode.txt | awk 'NR=='$i'');
        decoded=$(echo $text | base64);
        sed -i 's/'$text'/'$decoded'/g' ~/to_encode.txt;
    done

**4.** Script care afiseza, pentru fiecare utilizator de pe sistem, mesajul "Run, \<user>, run!" unde \<user> este inlocuit cu numele utilizatorului.

    #!/bin/bash
    users=$(cat /etc/passwd | cut -d: -f1)
    for i in ${users[@]};
    do
            echo "Run, "$i", run!"
    done

**5.** Script-ul extins de la subpunctul anterior astfel incat sa afiseze mesajul "Run, \<user>, run!" pentru utilizatorul curent atunci cand este rulat cu argumentul "me".

    #!/bin/bash
    users=$(cat /etc/passwd | cut -d: -f1)
    if ! [ -z $1 ] then
        if [ $1="me" ] then
            echo "Run, "$(whoami)", run!"
        fi
    else
        for i in ${users[@]};
        do
                echo "Run, "$i", run!"
        done
    fi

**6.** Script care afsieaza doar adresa IPv4 a unui domeniu primit ca argument in linia de comanda. Extindeti script-ul de la subpunctul anterior astfel incat la primirea unui al doilea argument, "v6", sa afiseze doar adresa IPv6 a domeniului primit ca prim argument.

    touch script.sh
    nano script.sh'

Continut script:

    #!/bin/bash

    domeniu=$1
    if ! [ -z "$2" ]; then
            if ! [ $2 = "v6" ]; then
                        host "$domeniu" | grep -v "IPv6" | awk '{print $4}'
            else
                        host "$domeniu" | grep "IPv6" | awk '{print $5}'
            fi
    else
            host "$domeniu" | grep -v "IPv6" | awk '{print $4}'
    fi

    ./script.sh www.google.com - Dovada c)
    ./script.sh www.google.com v6 - Dovada d)

**7.** Script care primeste ca argument un sir de 5 caractere, aplica algoritmul de encodare base64 pe acesta si scrie rezultatul la finalul unui

fisier numit ”passwords.txt“.

    touch hash_it.sh
    nano hash_it.sh

Continut script:

    #!/bin/bash

    echo $1 | base64 >> passwords.txt

    ./script.sh stringrandom - Dovada

**8.** Script care primeste ca argument numele unui utilizator. Daca acesta exista, script-ul va afisa data ultimei autentificari a acestuia. Astfel, il va adauga in sistem.

    nano 3d.sh
    chmod +x 3d.sh

Continut script:

    #!/bin/bash
    user="$1"

    /bin/egrep -i "^${user}:" /etc/passwd
    if [ $? -eq 0 ]; then
        lastlog -u $1
    else
        sudo useradd ${user}
    fi

**9.** Oneliner care instaleaza utilitarul "tree" daca acesta nu exista in sistem, sau il dezinstaleaza in caz contrar.

Continut script:

    #! /bin/bash

    sudo apt-get --yes install tree > temp.txt
    if ! [ -z $(grep "sudo apt autoremove" temp.txt) ]; then
        sudo apt-get --yes remove tree

**10.** Script care primeste ca argument doua numere pozitive si afiseaza toate numrele din intervalul inchis determinat de cele doua argumente.

    #!/bin/bash

    if [ "$1" -gt "$2" ]
    then
        for i in $(seq $2 $1); do
            echo $i
        done
    else
        for 9 in $(seq $1 $2); do
            echo $i
        done
    fi

**11.** Script care sa parseze fisierul ”users.csv“ si sa creeze cate un utilizator cu datele din fisier (nume si parola ̆).

    nano 2b.sh
    chmod +x 2b.sh

Continut script:

    #! /bin/bash
    cat users.csv | tail -n + 2 > fisier_temp.txt
    while read -r linie;
    do
        utilizator=$(echo $linie | awk -F "," '{print $1}')
        parola=$(echo $linie | awk "," '{print $2}')
        sudo useradd -p $(openssl passwd -1 $parola) $utilizator
    done < fisier_temp.txt
    rm -rf fisier_temp.txt

**12.** Script care primeste un numar variabil de parametrii de tip intreg si calculeaza suma acestora.

    nano 2d.sh
    chmod +x 2d.sh

Continut script:

    #! /bin/bash
    sum=0

    for i do
        sum=$(expr $sum + $i)
    done
    echo $sum

**13.** Script care modifica numele fisierelor ”.jpeg“, adaugand sufixul cat inaintea extensiei ”.jpeg“ si converteste fisierul redenumit intr-un fisier de tip png.. (Hint: man convert).

    touch script3b.sh
    nano script3b.sh

Continut script:

    #!/bin/bash

    cd cats/
    for i in _.jpeg; do mv ${i} ${i%.jpeg}\_cat.jpeg ; convert ${i%.jpeg}\_cat.jpeg ${i%.jpeg}\_cat.png; done
    for i in _.jpeg; do rm -rf ${i}; done

**14.** Script care genereaza o parola de lungimea indicata de primul argument al scriptului care contine caractere alfabetice daca al doilea argument al scriptului este ”alfa“ sau caractere alfanumerice daca al doilea argument al scriptului este ”alfanum“.

    touch task4b.sh
    nano task4b.sh

Continut script:

    #!/bin/bash

    lungime_parola=$1
    tip_parola=$2

    if [ "$tip_parola" = "alfa" ]; then
        tr -dc 'a-zA-Z' < /dev/urandom | fold -w $lungime_parola | head -n 1
    elif [ "$tip_parola" = "alfanum" ]; then
        tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w $lungime_parola | head -n 1
    fi

**15.** Script care genereaza o parola cu caractere alfanumerice aleatoare. Lungimea parolei va fi data ca argument in linia de comanda.

    nano 2d.sh
    chmod +x 2d.sh

Continut script:

    lungime=$1
    tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w $lungime | head -n 1

**16.** Script care primeste un sir de caractere ca argument si afiseaza hash-ul md5 al acestui sir. Daca scriptul nu primeste niciun argument, acesta trebuie sa intoarca codul de eroare 1.

    nano 5c.sh
    chmod +x 5c.sh

Continut script:

    #! /bin/bash

    input=$1

    if ! [ $## -eq 0 ]; then
        echo -n $input | md5sum | awk '{print $1}'
    else
        echo "1"
    fi

**17.** Script care primeste ca argument in linie de comanda un nummar de telefon. Scriptul va afisa "Numarul de telefon este valid" daca numarul
de telefon este de forma "07xxxxxxxx", unde ”x“ este o cifra. Altfel se va afisa ”Eroare“.

    #! /bin/bash

    text=$1

    contor=0

    cifre=()

    for ((i = 0; i < ${#text}; ++i)); do
        cifre+=( "${text:i:1}")
        contor=$((contor+1))
    done

    if [ "$contor" = "10" ]; then
        if [ "${cfire[0]}" = "0" ] && [ "${cifre[1]}" = "7" ]; then
            echo "Numarul de telefon este valid"
        else
            echo "Eroare
        fi
    else [ "$contor" = "12" ]; then
        if [ "${cifre[0]}" = "+" ] && [ "${cifre[1]}" = "4" ] && [ "${cifre[2]}" = "0" ] && [ "${cifre[3]}" = "7" ]; then
            echo "Numarul de telefon este valid"
        else
            echo "Eroare"
        fi
    else [ "$contor" = "13" ]; then
        if [ "${cifre[0]}" = "0" ] && [ "${cifre[1]}" = "0" ] && [ "${cifre[2]}" = "4" ] && [ "${cifre[3]}" = "0" ] && [ "${cifre[4]}" = "7" ]; then
            echo "Numarul de telefon este valid"
        else
            echo "Eroare"
        fi
    else
        echo "Eroare"
    fi
