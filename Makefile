all: arpproxy
	sudo ./arpproxy stdout

debug: arpproxy
	sudo ./arpproxy stdout debug

arpproxy: Makefile arpproxy.c arpproxy.h recvstate.h recvstate.c parsenl.h parsenl.c
	gcc -O2 -ggdb -Werror -Wall arpproxy.c recvstate.c parsenl.c -o arpproxy

install: arpproxy arpproxy.service
	sudo cp ./arpproxy.service /lib/systemd/system/
	sudo chmod 644 /lib/systemd/system/arpproxy.service
	sudo cp ./arpproxy /usr/sbin/
	sudo systemctl daemon-reload
	sudo systemctl enable arpproxy.service
	sudo systemctl start arpproxy.service

uninstall:
	sudo systemctl stop arpproxy.service
	sudo systemctl disable arpproxy.service
	sudo rm /lib/systemd/system/arpproxy.service
	sudo rm /usr/sbin/arpproxy
	sudo systemctl daemon-reload

reinstall: arpproxy uninstall install
