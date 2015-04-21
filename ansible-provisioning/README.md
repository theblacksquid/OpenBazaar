# Installing Open Bazaar in a Vagrant vm
You need to have the ansible package installed (available by brew for Mac and by apt-get for Ubuntu).
 Then, simply run 
```
vagrant up
````
from this directory or its parent. 

If you get any messages of the machine already having been provisioned, do:
```
vagrant provision
```
Now you should be able to visit Open Bazaar at:
http://192.168.33.10:55555/

If you get connection errors, edit your ~/.ssh/config to have this line:
```
# for vagrant provisioning
Host 127.0.0.1
    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null
```

# Installing Open Bazaar in machine(s) where you have ssh access to

Write a host name in every line of the file hosts.conf for every host you want to install Open Bazaar on. You need a user with sudo access.
You can either modify the vars section in openbazaar_linux.yml to change them with your preferred values or specify them at the command line as extra-vars (command line vars will override the vars in the yml file)
Example:

```
ansible-playbook openbazaar_linux.yml -i hosts.conf -u ssh_user --private-key=~/path/to/private/key -vvvv --extra-vars "do_system_update=False port=22222"
```
