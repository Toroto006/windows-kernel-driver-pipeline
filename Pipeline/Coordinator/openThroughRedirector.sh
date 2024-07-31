#! /bin/bash

# This script opens the redirect SSH tunnel to open the coordinator through the redirector
# don't forget to open the correct firewall ports

# CONFIGURATION
REDIRECTOR_IP=TODO
SSH_PRIVATE_KEY_PATH=./sshKey/id_redirector

# RUNNING
# open the reverse portforward from a screen session
# remember to configure the redirector correctly: https://serverfault.com/questions/861909/ssh-r-make-target-host-accept-connection-on-all-interfaces
# when nothing comes through the tunnel dies (prob. bc of firewalls) --> autossh
RPW_CMD="autossh -M 20000 -N -T -R 0.0.0.0:5000:localhost:5000 -i $SSH_PRIVATE_KEY_PATH root@$REDIRECTOR_IP"
echo "Running in screen: $RPW_CMD"
screen -dmS redirector $RPW_CMD