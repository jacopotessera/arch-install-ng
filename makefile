.PHONY: check-cfg print-cfg cfg sh-cfg virsh-domain wifi eth partition ssh-copy chroot

MAKEFILE_JUSTNAME := $(firstword $(MAKEFILE_LIST))
MAKEFILE_COMPLETE := $(CURDIR)/$(MAKEFILE_JUSTNAME)

CONFIGURATION_JUSTNAME := $(ARCH_INSTALL_CONFIGURATION)
CONFIGURATION_COMPLETE := $(CURDIR)/$(CONFIGURATION_JUSTNAME)

PACMAN := pacman -Sy --noconfirm
SWAY := Y

WIRELESS_INTERFACE := $(ARCH_INSTALL_WIRELESS_INTERFACE)
SSID := $(ARCH_INSTALL_SSID)
PASSWORD := $(ARCH_INSTALL_PASSWORD)

DISK := $(ARCH_INSTALL_DISK)
P := $(ARCH_INSTALL_P)

IP := $(ARCH_INSTALL_IP)
HOSTNAME := $(ARCH_INSTALL_HOSTNAME)
USER := $(ARCH_INSTALL_USER)
IDENTITY_FILE := $(ARCH_INSTALL_IDENTITY_FILE)

check-cfg:
ifeq ($(CONFIGURATION_JUSTNAME),)
	@echo "Run 'source configure.{fish,sh}'"
	@exit 1
endif	

print-cfg:
	@echo -e 'ARCH INSTALL CONFIGURATION:'
	@echo -e '\tMAKEFILE: $(MAKEFILE_COMPLETE)'
	@echo -e '\tCONFIGURATION FILE: $(CONFIGURATION_COMPLETE)'
	@echo -e '\tWIRELESS_INTERFACE: $(WIRELESS_INTERFACE)'
	@echo -e '\tSSID: $(SSID)'
	@echo -e '\tPASSWORD: $(PASSWORD)'
	@echo -e '\tDISK: $(DISK)'
	@echo -e '\tP: $(P)'
	@echo -e '\tIP: $(IP)'
	@echo -e '\tHOSTNAME: $(HOSTNAME)'
	@echo -e '\tUSER: $(USER)'
	@echo -e '\tIDENTITY_FILE: $(IDENTITY_FILE)'

cfg: check-cfg print-cfg

sh-cfg: cfg
	@echo 'export ARCH_INSTALL_CONFIGURATION=configure.sh' > configure.sh
	@echo "export ARCH_INSTALL_WIRELESS_INTERFACE='$(ARCH_INSTALL_WIRELESS_INTERFACE)'" >> configure.sh
	@echo "export ARCH_INSTALL_SSID='$(ARCH_INSTALL_SSID)'" >> configure.sh
	@echo "export ARCH_INSTALL_PASSWORD='$(ARCH_INSTALL_PASSWORD)'" >> configure.sh
	@echo "export ARCH_INSTALL_DISK='$(ARCH_INSTALL_DISK)'" >> configure.sh
	@echo "export ARCH_INSTALL_P='$(ARCH_INSTALL_P)'" >> configure.sh
	@echo "export ARCH_INSTALL_IP='$(ARCH_INSTALL_IP)'" >> configure.sh
	@echo "export ARCH_INSTALL_HOSTNAME='$(ARCH_INSTALL_HOSTNAME)'" >> configure.sh
	@echo "export ARCH_INSTALL_USER='$(ARCH_INSTALL_USER)'" >> configure.sh
	@echo "export ARCH_INSTALL_IDENTITY_FILE='$(ARCH_INSTALL_IDENTITY_FILE)'" >> configure.sh

iwctl:
	@iwctl --passphrase="$(PASSWORD)" station "$(WIRELESS_INTERFACE)" connect "$(SSID)"

wifi: cfg
	@sudo $(PACMAN) wpa_supplicant
	@echo '#!/bin/bash' > wifi.sh
	@echo "WIRELESS_INTERFACE='$(WIRELESS_INTERFACE)'" >> wifi.sh
	@echo "SSID='$(SSID)'" >> wifi.sh
	@echo "PASSWORD='$(PASSWORD)'" >> wifi.sh
	@echo 'wpa_supplicant -i $${WIRELESS_INTERFACE} -c <(wpa_passphrase  $${SSID} $${PASSWORD})' >> wifi.sh
	@chmod +x wifi.sh

eth: cfg
	@echo eth

prepare:
	#echo "root:root" | chpasswd
	passwd
	systemctl start sshd

virsh-domain: cfg
	sudo qemu-img create -f qcow2 "/var/lib/libvirt/images/$(HOSTNAME).qcow2" 20G
	sed 's/{{HOSTNAME}}/'$(HOSTNAME)'/g' base-archlinux.xml | sudo virsh define /dev/stdin
	sudo virsh start $(HOSTNAME)

ssh-copy: sh-cfg
	$(eval IP := $(shell sudo virsh domifaddr $(HOSTNAME) | grep ipv4 | awk '{print $$4}' | cut -d"/" -f1 | tail -n 1))
	mkdir -p ~/.ssh/config.d/$(HOSTNAME)
	ssh-keygen -t rsa -b 4096 -q -N "" -f ~/.ssh/config.d/$(HOSTNAME)/id_rsa
	sshpass -p root ssh-copy-id -i ~/.ssh/config.d/$(HOSTNAME)/id_rsa.pub -o "IdentityFile ~/.ssh/config.d/$(HOSTNAME)/id_rsa" -oStrictHostKeyChecking=no -p 22 root@$(IP)
	echo "Host $(HOSTNAME)-install" > ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	User root" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	HostName $(IP)" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	Port 22" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	IdentityFile ~/.ssh/config.d/$(HOSTNAME)/id_rsa" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "Include ~/.ssh/config.d/$(HOSTNAME)/config" >> ~/.ssh/config
	scp $(MAKEFILE_COMPLETE) $(HOSTNAME)-install:/
	scp $(CONFIGURATION_COMPLETE) $(HOSTNAME)-install:/
	scp configure.sh $(HOSTNAME)-install:/
	ssh -t $(HOSTNAME)-install "pacman -Sy --noconfirm make"
	ssh -t $(HOSTNAME)-install "source /configure.sh && make -f /makefile cfg"

ssh: cfg
	$(eval IP := $(shell sudo virsh domifaddr $(HOSTNAME) | grep ipv4 | awk '{print $$4}' | cut -d"/" -f1 | tail -n 1))
	mkdir -p ~/.ssh/config.d/$(HOSTNAME)
	ssh-keygen -t rsa -b 4096 -q -N "" -f ~/.ssh/config.d/$(HOSTNAME)/id_rsa
	sshpass -p $(USER) ssh-copy-id -i ~/.ssh/config.d/$(HOSTNAME)/id_rsa.pub -o "IdentityFile ~/.ssh/config.d/$(HOSTNAME)/id_rsa" -oStrictHostKeyChecking=no -p 22 $(USER)@$(IP)
	echo "Host $(HOSTNAME)" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	User $(USER)" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	HostName $(IP)" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	Port 22" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "	IdentityFile ~/.ssh/config.d/$(HOSTNAME)/id_rsa" >> ~/.ssh/config.d/$(HOSTNAME)/config
	echo "Include ~/.ssh/config.d/$(HOSTNAME)/config" >> ~/.ssh/config

partition: cfg
	parted /dev/$(DISK) mklabel gpt
	parted /dev/$(DISK) mkpart fat32 1M 512M
	parted /dev/$(DISK) mkpart ext4 512M 100%

	mkfs.fat -F 32 -n boot /dev/$(DISK)$(P)1
	mkfs.ext4 /dev/$(DISK)$(P)2 

	mount /dev/$(DISK)$(P)2 /mnt
	mkdir -p /mnt/boot
	mount /dev/$(DISK)$(P)1 /mnt/boot

	pacstrap /mnt base base-devel linux linux-firmware
	genfstab -U /mnt >> /mnt/etc/fstab

chroot:
	mkdir -p /mnt/root/.ssh/
	cp ~/.ssh/authorized_keys /mnt/root/.ssh/authorized_keys
	cp /makefile /mnt/makefile
	cp /configure.sh /mnt/configure.sh
	arch-chroot /mnt source /configure.sh && make -f /makefile cfg
	
datetime:
	ln -sf /usr/share/zoneinfo/Europe/Rome /etc/localtime
	$(PACMAN) ntp
	ntpd -gq
	hwclock --systohc

locale:
	sed -i 's/#en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen
	locale-gen
	echo "LANG=en_US.UTF-8" > /etc/locale.conf
	echo "KEYMAP=us_intl" > /etc/vconsole.conf

user: cfg
	$(PACMAN) sudo neovim fish
	useradd -m $(USER) -s /bin/fish
	usermod -a -G wheel,video,input $(USER)
	echo "$(USER):$(USER)" | chpasswd
	ln -s /usr/bin/nvim /usr/bin/vi
	ln -s /usr/bin/nvim /usr/bin/vim
	EDITOR=vi visudo
	mkdir -p /home/$(USER)/.config/fish/
	echo '# Start X at login' > /home/$(USER)/.config/fish/config.fish
	echo 'if status is-login' >> /home/$(USER)/.config/fish/config.fish
	echo '  if test -z "$$DISPLAY" -a "$$XDG_VTNR" = 1' >> /home/$(USER)/.config/fish/config.fish
ifeq ($(SWAY),Y)
	echo '    sway' >> /home/$(USER)/.config/fish/config.fish
else	
	echo '    exec startx -- -keeptty' >> /home/$(USER)/.config/fish/config.fish
endif
	echo '  end' >> /home/$(USER)/.config/fish/config.fish
	echo 'end' >> /home/$(USER)/.config/fish/config.fish
	chown -R $(USER):$(USER) /home/$(USER)/
	chown $(USER):$(USER) /home/$(USER)/.config/fish/config.fish

grub:
	$(PACMAN) grub efibootmgr
	grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=grub
	sed -i 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=0/' /etc/default/grub
	grub-mkconfig -o /boot/grub/grub.cfg

mk-eth:
	$(PACMAN) netctl dhcp dhcpcd openssh
	$(eval ETH_INTERFACE := $(shell ip a | grep "2: " | cut -d" " -f2))
	echo "Description=eth" > /etc/netctl/eth
	echo "Interface=$(ETH_INTERFACE)" >> /etc/netctl/eth
	echo "Connection=ethernet" >> /etc/netctl/eth
	echo "IP=dhcp" >> /etc/netctl/eth
	netctl enable eth
	echo "nameserver 1.1.1.1" > /etc/resolv.conf
	systemctl enable sshd

mk-wifi:
	$(PACMAN) netctl dhcp dhcpcd openssh wpa_supplicant
	echo "Description=wifi" > /etc/netctl/wifi
	echo "Interface=wlp31s0" >> /etc/netctl/wifi
	echo "Connection=wireless" >> /etc/netctl/wifi
	echo "Security=wpa" >> /etc/netctl/wifi
	echo "IP=dhcp" >> /etc/netctl/wifi
	echo "ESSID=\"Home&Life SuperWiFi-6CB9\"" >> /etc/netctl/wifi
	echo "Key=TB3KHN8DQLNMDM8H" >> /etc/netctl/wifi
	netctl enable wifi
	echo "nameserver 1.1.1.1" > /etc/resolv.conf
	systemctl enable sshd

system: cfg
	echo $(HOSTNAME) > /etc/hostname
	mkinitcpio -P
	echo "root:root" | chpasswd

mk-fstab: cfg
	mkdir -p /mnt/evo-pro
	echo "/dev/nvme0n1p1 /mnt/evo-pro ext4 rw,relatime 0 0" >> /etc/fstab
	chown $(USER) /mnt/evo-pro

libvirt:
	$(PACMAN) qemu libvirt firewalld virt-manager polkit edk2-ovmf dnsmasq
	usermod -a -G libvirt,kvm $(USER)
	systemctl enable libvirtd firewalld
	virsh net-autostart default
	#sudo virsh net-list --all
	#sudo vi /etc/mkinitcpio.conf
	#sudo vi /etc/modprobe.d/vfio.conf
	#ls /dev/input/by-id/
	#sudo vi /etc/libvirt/qemu.conf
	#sudo pacman -S pulseaudio
	#sudo systemctl --user enable --now  pulseaudio.service

.ONESHELL:
qemu-test:
	sudo $(PACMAN) git spice-protocol python2 ceph libiscsi glusterfs
	git clone https://github.com/spheenik/qemu.git
	mkdir qemu/build
	cd qemu/build
	../configure --prefix=/opt/qemu-test --python=/usr/bin/python2 --target-list=x86_64-softmmu --audio-drv-list=pa --disable-werror
	make -j 16
	sudo make install

autologin: cfg
	mkdir -p /etc/systemd/system/getty@tty1.service.d/
	echo "[Service]" > /etc/systemd/system/getty@tty1.service.d/override.conf
	echo "ExecStart=" >> /etc/systemd/system/getty@tty1.service.d/override.conf
	echo 'ExecStart=-/usr/bin/agetty --autologin $(USER) --noclear %I $$TERM' >> /etc/systemd/system/getty@tty1.service.d/override.conf
	systemctl enable getty@tty1

x11vnc:
	$(PACMAN) x11vnc
	mkdir -p /etc/systemd/system/x11vnc.service.d/
	echo "[Service]" > /etc/systemd/system/x11vnc.service.d/override.conf
	echo "ExecStart=" >> /etc/systemd/system/x11vnc.service.d/override.conf
	echo "ExecStart=/usr/bin/x11vnc -localhost -forever -nevershared -auth guess -display :0 -rfbport 6900 -xdamage" >> /etc/systemd/system/x11vnc.service.d/override.conf
	echo "[Install]" >> /etc/systemd/system/x11vnc.service.d/override.conf
	echo "WantedBy=graphical.target" >> /etc/systemd/system/x11vnc.service.d/override.conf
	systemctl enable x11vnc.service

i3: cfg
	pacman -S --noconfirm xorg xorg-xinit i3 dmenu i3status-rust 
	echo "xset led 3 &" > /home/$(USER)/.xinitrc
	echo "setxkbmap it &" >> /home/$(USER)/.xinitrc
	echo "exec i3" >> /home/$(USER)/.xinitrc

sway:
	pacman -S --noconfirm sway i3status-rust bemenu
	mkdir -p /home/$(USER)/.config/sway
	touch /home/$(USER)/.config/sway/config
	
docker:
	pacman -S git docker docker-compose
	systemctl enable docker
	#git clone https://github.com/deviantony/docker-elk.git
	#cd docker-elk
	#docker-compose up
	
firefox:
	pacman -S --noconfirm firefox geckodriver python-poetry alacritty tmux
	#poetry install
	#poetry run pytest tests/ --cov=next_run_calculator --cov-report html --cov-report term-missing
cuda:
	$(PACMAN) nvidia cuda

all: datetime locale sway grub mk-eth user autologin firefox
