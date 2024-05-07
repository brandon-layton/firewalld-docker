#! /bin/bash
#
# Author: Brandon Layton
#
#
# Thanks to Eric Garver for the method to get this all working.
# You can read his amazing artice here:
# https://firewalld.org/2024/04/strictly-filtering-docker-containers
#
# Based on the idea from ufw-docker and ufw-docker-automated
# https://github.com/chaifeng/ufw-docker
# https://github.com/shinebayar-g/ufw-docker-automated

# Text color variables
txtund=$(tput sgr 0 1)          # Underline
txtbld=$(tput bold)             # Bold
bldred=${txtbld}$(tput setaf 1) #  red
bldblu=${txtbld}$(tput setaf 4) #  blue
txtrst=$(tput sgr0)             # Reset

print_usage () {
        echo -e "Usage:\tsetup-firewalld.sh -u\t\t\t\tSetup firewalld iptables instead of docker"
        echo -e "\tsetup-firewalld.sh -h, --help\t\t\tDisplay this usage message"
}


check_root () {
        # Needs to run as root
        if [ `id -u` -ne 0 ]
          then echo Please run this script as root or using sudo!
          exit
        fi
}

modify_daemon () {

        echo "This action requires a reboot, continue?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) break ;;
                No ) return ;;
            esac
        done

        # save docker dir
        configPath=/etc/docker/daemon.json
        # turn off ip tables
        jq '.iptables = false' $configPath > $configPath.tmp && mv $configPath.tmp $configPath \
        || echo '{"iptables":false}' | jq . > $configPath \
        && rm $configPath.tmp

        echo "$bldblu""All changes applied, starting reboot""$txtrst"
        reboot
}

check_daemon () {
	if ! `docker info 2>&1 | grep -qe "iptables.*disabled"`; then
		modify_daemon
	fi
}

remove_sources () {
	for subnet in `firewall-cmd --permanent --zone docker --list-sources`; do
		firewall-cmd --permanent --zone docker --remove-source $subnet
	done
}

add_sources () {
	remove_sources

	for subnet in `docker network inspect $(docker network ls | awk '$3 == "bridge" { print $1}') | jq -r '.[] | .IPAM.Config[0].Subnet' -`; do
		firewall-cmd --permanent --zone docker --add-source $subnet
	done
}

setup_policy () {
	firewall-cmd --permanent --delete-policy dockerToWorld 
	firewall-cmd --permanent --new-policy dockerToWorld 
	firewall-cmd --permanent --policy dockerToWorld --add-ingress-zone docker 
	firewall-cmd --permanent --policy dockerToWorld --add-egress-zone ANY 
	firewall-cmd --permanent --policy dockerToWorld --set-target ACCEPT 
	firewall-cmd --permanent --policy dockerToWorld --add-masquerade 
}

publish_ports () {
	# delete old rules
	firewall-cmd --permanent --delete-policy dockerFwdPort
	for ipset_name in $(firewall-cmd --permanent --get-ipsets | sed 's/\s\+/\n/g' | grep -e "^managed"); do
		firewall-cmd --permanent --delete-ipset="$ipset_name"
	done

	# make new rules
	firewall-cmd --permanent --new-policy dockerFwdPort
	firewall-cmd --permanent --policy dockerFwdPort --add-ingress-zone ANY
	if { firewall-cmd --version; echo "2.0.0"; } | sort --version-sort --check;
	then
		# firewalld is less than version 2.0.z and requires any instead of host
		firewall-cmd --permanent --policy dockerFwdPort --add-egress-zone ANY
	else
		firewall-cmd --permanent --policy dockerFwdPort --add-egress-zone HOST
	fi

	# find containers that are managed
	for container_id in `docker ps -qf 'label=FIREWALLD_MANAGED'`; do

		# Use docker inspect to get container details in JSON format
		container_info=$(docker inspect --format='{{json .NetworkSettings}}' "$container_id" \
			| jq -cr '.Networks[].IPAddress as $container_ip | .Ports | to_entries[] | .key as $container_port | .value[] | 
			{ container_port: ($container_port | split("/") | .[0]), container_ip: $container_ip, host_port: .HostPort, host_ip: .HostIp, 
			ip_version: (.HostIp | if test(":") then "ipv6" else "ipv4" end), protocol: ($container_port | split("/") | .[1]) }')
			
		
		# create ip set for this container if there is a whitelist
		allow_from_v4=$(docker inspect --format='{{json .Config.Labels.FIREWALLD_ALLOW_FROM_IPV4}}' $container_id | jq -cr 'if . then split(";")[] else . end')
		allow_from_v6=$(docker inspect --format='{{json .Config.Labels.FIREWALLD_ALLOW_FROM_IPV6}}' $container_id | jq -cr 'if . then split(";")[] else . end')

		# set ipv4 ip sets
		if [[ -z "$allow_from_v4" || "$allow_from_v4" == "null" ]];
		then 
			# no whitelist
			saddr_v4=""
		else
			# make an ip set for the whitelist
			firewall-cmd --permanent --new-ipset="managed-v4-$container_id" --type=hash:net

			# add each ip to the ip set
			for entry in $allow_from_v4; do
				firewall-cmd --permanent --ipset="managed-v4-$container_id" --add-entry=$entry

			done
			
			# set ipset as whitelist
			saddr_v4="source ipset=\"managed-v4-$container_id\""
		fi

		# set ipv6 ip sets
		if [[ -z "$allow_from_v6" || "$allow_from_v6" == "null" ]];
		then 
			# no whitelist
			saddr_v6=""
		else
			# make an ip set for the whitelist
			firewall-cmd --permanent --new-ipset="managed-v6-$container_id" --type=hash:net

			# add each ip to the ip set
			for entry in $allow_from_v6; do
				firewall-cmd --permanent --ipset="managed-v6-$container_id" --add-entry=$entry

			done
			
			# set ipset as whitelist
			saddr_v6="source ipset=\"managed-v6-$container_id\""
		fi

		# for every forwarded port on every container and external ip, can add a lot of rules
		for port_entry in $container_info; do

			# set variables for firewalld rich rule
			container_port=$(echo "$port_entry" | jq -cr 'try .container_port')
			container_ip=$(echo "$port_entry" | jq -cr 'try .container_ip')
			host_port=$(echo "$port_entry" | jq -cr 'try .host_port')
			host_ip=$(echo "$port_entry" | jq -cr 'try .host_ip')
			ip_version=$(echo "$port_entry" | jq -cr 'try .ip_version')
			protocol=$(echo "$port_entry" | jq -cr 'try .protocol')

			# check if the ips are v6 v4 or a mix
			if [[ "$host_ip" == *"."* && "$container_ip" == *"."* ]];
			then
				saddr="$saddr_v4"

			elif [[ "$host_ip" == *":"* && "$container_ip" == *":"* ]];
			then
				saddr="$saddr_v6"

			else
				# we don't add the rules if the ip protocol does not match
				continue
			fi

			# destination ip  if it is not just default
			case $host_ip in
				"::" | "0.0.0.0" )
					daddr=""
					;;

				* )
					daddr="destination address=\"$host_ip\""
					;;
			esac

			# make ruch rule, this is all the magic
			richrule="rule family=$ip_version $saddr $daddr forward-port port=$host_port protocol=$protocol to-port=$container_port to-addr=\"$container_ip\""
			firewall-cmd --permanent --policy dockerFwdPort --add-rich-rule="$richrule"
		done

	done
}

# run checks
check_root

case "$1" in
        -h )
                print_usage
                ;;
        --help ) 
                print_usage
                ;;
        -u )
		check_daemon

		add_sources 
		setup_policy
		publish_ports
		firewall-cmd --reload
                ;;
        * )
                echo "$bldred""ERROR: Invalid option: $1""$txtrst"
                print_usage
esac

echo "end"
