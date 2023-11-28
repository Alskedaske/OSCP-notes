General Course Information

To connect to Module Exercise VMs that require SSH connection:
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```

To find the .ovpn file:
```bash
sudo updatedb
locate universal.ovpn
```
Go to directory, then:
```bash
mkdir /home/kali/offsec
mv universal.ovpn /home/kali/offsec/universal.ovpn
cd ../offsec
```
Connect using openvpn
```bash
sudo openvpn universal.ovpn
```
Interface: TUN0. IP: 192.168.45.x/24

Machines will contain either local.txt or proof.txt or both
```bash

```
```bash

```
```bash

```
```bash

```
