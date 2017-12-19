# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.box = "bento/ubuntu-17.10"
    config.vm.provision "shell", inline: <<-SHELL
        sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
        echo "deb https://repo.iovisor.org/apt/artful artful main" | sudo tee /etc/apt/sources.list.d/iovisor.list
        sudo apt-get update
        sudo apt-get install -y bcc-tools libbcc-examples linux-headers-$(uname -r) golang git \
        build-essential cmake llvm-3.8 libclang-3.8-dev bison python zlib1g-dev libelf-dev flex \
        libedit-dev
        git clone https://github.com/iovisor/bcc.git
        mkdir bcc/build; cd bcc/build
        git checkout v0.3.0
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr
        make
        sudo make install
        mkdir -p /home/vagrant/go/src/github.com/cpg1111/ /home/vagrant/go/pkg/ /home/vagrant/go/bin/
        sudo ln -s /vagrant /home/vagrant/go/src/github.com/cpg1111/pprof-ebpf
        echo "export GOPATH=/home/vagrant/go/" >> /home/vagrant/.bashrc
    SHELL
end
