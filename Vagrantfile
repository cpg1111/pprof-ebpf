# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.box = "ubuntu/xenial64"
    config.vm.provision "shell", inline: <<-SHELL
        sudo apt-get update
        sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
        libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev golang
        git clone https://github.com/iovisor/bcc.git
        mkdir bcc/build; cd bcc/build
        git checkout v0.3.0
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr
        make
        sudo make install
    SHELL
end
