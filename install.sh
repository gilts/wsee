# !/bin/bash env

echo [Installation Script]
echo
ansi='<Choose>: '
opti=("WSee" "ZGrab" "Fix OpenSSL" "Fix ZGrab")

select ch in "${opti[@]}"; do
    case $ch in
        "WSee")
			apt install python3, python3-pip
			apt install git
			git clone https://github.com/MC874/wsee
			cd wsee
			chmod +x *
            python3 -m pip install requests
			echo Done!
            ;;
        "ZGrab")
            cd wsee
			chmod +x *
			git clone https://github.com/PalindromeLabs/zgrab2
			cd zgrab2
			sudo make
			sudo update-alternatives /usr/bin/zgrab2 zgrab2 ./zgrab2
			echo Done!
            ;;
        "Fix OpenSSL")
            cd wsee
			chmod +x *
			SC=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
			export OPENSSL_CONF=$SC/wsee/openssl.cnf
            ;;
		"Fix ZGrab")
			sudo rm -rf /etc/resolv.conf
			echo "nameserver 1.1.1.1" >> /etc/resolv.conf
			echo Done!
			;;
	"Quit")
	    echo "User requested exit"
	    exit
	    ;;
        *) echo "invalid option $REPLY";;
    esac
done