# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # All Vagrant configuration is done here. The most common configuration
  # options are documented and commented below. For a complete reference,
  # please see the online documentation at vagrantup.com.

  # Every Vagrant virtual environment requires a box to build off of.
  config.vm.box = "trusty32"
  config.vm.box_url = "https://cloud-images.ubuntu.com/vagrant/trusty/current/trusty-server-cloudimg-i386-vagrant-disk1.box"
 
  config.vm.provision "ansible" do |ansible|
     ansible.playbook = "ansible-provisioning/openbazaar_linux.yml"
     ansible.verbose = true
     # can change provisioning config using extra vars:
     # ansible.extra_vars = { from_github: false, copy_from_local_directory: '/home/users/Projects/OpenBazaar-clean/' } 
  end

  #This stanza makes use of the vagrant-cachier tool to cache apt updates while refreshing virtual machines -sbl
  if Vagrant.has_plugin?("vagrant-cachier")
     # Cached packages are no longer shared between instances of the same base box.
     # See: https://github.com/OpenBazaar/OpenBazaar/issues/650
     config.cache.scope = :machine

     # If you are using VirtualBox, you might want to use that to enable NFS for
     # shared folders. This is also very useful for vagrant-libvirt if you want
     # bi-directional sync
     config.cache.synced_folder_opts = {
       type: :nfs,
       # The nolock option can be useful for an NFSv3 client that wants to avoid the
       # NLM sideband protocol. Without this option, apt-get might hang if it tries
       # to lock files needed for /var/cache/* operations. All of this can be avoided
       # by using NFSv4 everywhere. Please note that the tcp option is not the default.
       mount_options: ['rw', 'vers=3', 'tcp', 'nolock']
     }
   end

  config.vm.synced_folder ".", "/vagrant",  :mount_options => ["dmode=755,fmode=755"]

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  config.vm.network "private_network", ip: "192.168.33.10"

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine.
  config.vm.network "forwarded_port", guest: 8888, host: 8888
  config.vm.network "forwarded_port", guest: 8889, host: 8889
  config.vm.network "forwarded_port", guest: 8890, host: 8890
  config.vm.network "forwarded_port", guest: 12345, host: 12345

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Don't boot with headless mode
  #   vb.gui = true
  #
  #   # Use VBoxManage to customize the VM. For example to change memory:
  #   vb.customize ["modifyvm", :id, "--memory", "1024"]
  # end
  #
  # View the documentation for the provider you're using for more
  # information on available options.

end
