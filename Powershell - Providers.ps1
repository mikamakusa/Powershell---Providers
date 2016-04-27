function Provider {
    Param(
        [Parameter(Mandatory=$true,position = 0)][string]$Name,
        [Parameter(Mandatory=$true,position = 0)][ValidateSet("Insert","Remove","Reboot","Rebuild")][string]$Action,
        [Parameter(Mandatory=$false)][string]$VMName,
        [Parameter(Mandotory=$false)][string]$Image,
        [Parameter(Mandatory=$false)][string]$Size,
        [Parameter(Mandatory=$false)][string]$Region,
        [Parameter(Mandatory=$false)][string]$Password,
        [Parameter(Mandatory=$false)][string]$Number,
        [Parameter(Mandatory=$false)][string]$Token,
        [Parameter(Mandatory=$false)][string]$Tenant,
        [Parameter(Mandatory=$false)][string]$Username,        
        [Parameter(Mandatory=$false)][string]$APIKey,
        [Parameter(Mandatory=$false)][string]$Project,
        [Parameter(Mandatory=$false)][string]$AccessKey,
        [Parameter(Mandatory=$false)][string]$SecretKey,
        [Parameter(Mandatory=$false)][string]$ServerId,
        [Parameter(Mandatory=$false)][string]$Zone,
        [Parameter(Mandatory=$false)][ValidateSet("Classic","VPC")][string]$EC2Type
    )
    switch ($Name) {
        "Cloudwatt" {
            switch ($Action) {
                "Insert" {
                    # Version
                    $Version = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/ -Method Get).content | ConvertFrom-Json).versions).id
                    # Token
                    [xml]$auth = "<?xml version='1.0' encoding='UTF-8'?><auth xmlns='http://docs.openstack.org/identity/v2.0' tenantName='$Tenant'><passwordCredentials username='$Username' password='$Password'/></auth>"
                    [xml]$TokenRequest = Invoke-WebRequest -Uri "https://identity.fr1.cloudwatt.com/$Version/tokens" -ContentType "application/json" -Method Post -Headers @{"Accept" = "application/json"} -Body $auth
                    $Token = $TokenRequest.access.token.id
                    # Image
                    $ImageSet = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/images -Method Get -Headers @{"X-Auth-Token" = '"'+$Token+'"'}).content | ConvertFrom-Json).images | where name -EQ "$Image").id
                    # Size
                    $SizeSet = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/flavors -Method Get -Headers @{"X-Auth-Token" = '"'+$Token+'"'}).content | ConvertFrom-Json).flavors | where name -Match "$Size").id
                    # Security Group
                    $SGroup = (((Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/security-groups -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"security_group":{"name":"Security","description":"SecGroup"}}').content | ConvertFrom-Json).security_group).name
                    # Network
                    $NetworkId = (((Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/security-groups -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"network":{"name": "network1", "admin_state_up": true}}').content | ConvertFrom-Json).network).id
                    Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/security-groups -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"subnet":{"network_id":"'$NetworkId'","ip_version":4,"cidr":"192.168.0.0/24"}}'
                    # SSH (Keys & Auth) & Instance creation
                    if ($Image -notmatch "windows") {
                        # Key
                        $Key = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/os-keypairs -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Post -Body '{"keypair":{"name":"cle"}}').content | ConvertFrom-Json).keypair)
                        Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/security-group-rules -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Post -Body '{"security_group_rule":{"direction":"ingress","port_range_min":"22","ethertype":"IPv4","port_range_max":"22","protocol":"tcp","security_group_id":"'+$SgroupId+'"}}'
                        $ServerId = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Post -Body '{"server": {"name": "'+$VMName+'","imageRef": "'+$ImageSet+'","flavorRef": "'+$SizeSet+'","metadata": {"My Server Name": "'+$VMName+'"},"personality": [{"path": "~/.ssh/authorized_keys","contents": "'+$Key+'"}]}}').content | ConvertFrom-Json).server).id
                    }
                    else {
                        Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/security-group-rules -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Post -Body '{"security_group_rule":{"direction":"ingress","port_range_min":"3389","ethertype":"IPv4","port_range_max":"3389","protocol":"tcp","security_group_id":"'$SgroupId'"}}'
                        $ServerId = (((Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Post -Body '{"server":{"name":"'+$VMName+'","key_name":"cle","imageRef":"'+$ImageSet+'","flavorRef":"'+$SizeSet+'","max_count":'+$Number+',"min_count":1,"networks":[{"uuid":"'+$NetworkId+'"}],"metadata": {"admin_pass": "'+$Password+'"},"security_groups":[{"name":"default"},{"name":"'+$Sgroup+'"}]}}').content | ConvertFrom-Json).server).id
                    }
                    $NetId = ((((Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/networks -ContentType "application/json" -Method GET -Headers @{"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'}).content | ConvertFrom-Json).networks).id | where name -EQ "public")
                    $IP = (((((Invoke-WebRequest -Uri https://network.fr1.cloudwatt.com/$Version/floatingips -ContentType "application/json" -Method Post -Headers @{"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"floatingip":{"floating_network_id":"'+$NetId+'"}}').content) | ConvertFrom-Json).floatingip).floating_ip_address)
                    Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers/$ServerId/action -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"addFloatingIp":{"address":"'+$IP+'"}}'
                }
                "Remove" {
                    Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers/$ServerId -Method Delete -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'}
                }
                "Reboot" {
                    Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers/$ServerId/reboot -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body '{"reboot": {"type": "SOFT"}}'
                }
                "Rebuild" {
                    if ($Image -match "CoreOS" -or "CentOS" -or "Debian" -or "Ubuntu" -or "OpenSuse" -or "Fedora") {
                        $Body = '{"rebuild": {"imageRef": "'+$ImageSet+'","name": "'+$VMName+'","adminPass": "$Password","accessIPv4": "'+$IP+'","metadata": "personality": [{"path": "~/.ssh/authorized_keys","contents": "'+$Key+'"}]}}'
                        Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers/$ServerId/rebuild -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body $Body
                    }
                    else {
                        $Body = '{"server":{"name":"'+$VMName+'","key_name":"cle","imageRef":"'+$ImageSet+'","flavorRef":"'+$SizeSet+'","max_count":'+$Number+',"min_count":1,"networks":[{"uuid":"'+$NetworkId+'"}],"metadata": {"admin_pass": "'+$Password+'"},"security_groups":[{"name":"default"},{"name":"'+$Sgroup+'"}]}}'
                        Invoke-WebRequest -Uri https://compute.fr1.cloudwatt.com/$Version/$Tenant/servers/$ServerId/rebuild -Method Post -Headers @{"ContentType" = "application/json" ;"Accept" = "application/json";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body $Body
                    }
                }
                default {}
            }
        }
        "Numergy" {
            switch ($Action){
                "Insert" {
                    # Token
                    $Nversion = ((Invoke-WebRequest -Uri "https://api2.numergy.com/" -ContentType "application/json; charset=utf-8" -Method Get | ConvertFrom-Json).versions | select -Property id,status -Last 1).id
                    $Tbody = '{"auth": {"apiAccessKeyCredentials": {"accessKey": "'+$AccessKey+'","secretKey": "'+$SecretKey+'" },"tenantId": "'+$tenantId+'" } }'
                    $Token = (((((Invoke-WebRequest -Uri "https://api2.numergy.com/$Nversion/tokens" -ContentType "application/json; charset=utf-8" -Method Post -Body $TBody) | ConvertFrom-Json).access).token).id)
                    # Size
                    $SizeSet = ((((Invoke-WebRequest -Uri http://api2.numergy.com/$Version/$Tenant/flavors -Headers @{"ContentType" = "application/json; charset=utf-8";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Get).content) | ConvertFrom-Json).flavors | where name -EQ "$Size").id
                    # Image
                    $ImageSet = ((((Invoke-WebRequest -Uri http://api2.numergy.com/$Version/$Tenant/images -Headers -Headers @{"ContentType" = "application/json; charset=utf-8";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Get).content) | ConvertFrom-Json).images | where name -EQ "$Image").id
                    # Instance creation
                    $Uri = https://api2.numergy.com/$Nversion/$TenantID/servers
                    $Body = '{"server": {"flavorRef": "'+$SizeSet+'","imageRef": "'+$ImageSet+'","name": "'+$VMName+'"}}'
                    Invoke-WebRequest -Uri $Uri -Method Post -Headers @{"ContentType" = "application/json; charset=utf-8";"X-Auth-Token" = '"'+$TokenSet+'"'} -Body $Body
                }
                "Remove" {}
                "Reboot" {}
                "Rebuild" {}
                default {}
            }
        }
        "Rackspace" {
            switch ($Action) {
                "Insert" {
                    # Token
                    $Token = (((((Invoke-WebRequest -Uri https://identity.api.rackspacecloud.com/v2.0/tokens -Method Post -ContentType "application/json" -Body '{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"'+$Username+'","apiKey":"'+$apiKey+'"}}}') | ConvertFrom-Json).access).token).id)
                    # Size 
                    $SizeSet = ((((Invoke-WebRequest -Uri https://lon.servers.api.rackspacecloud.com/v2/$Tenant/flavors -Mehod Get -Headers -Headers @{"ContentType" = "application/json; charset=utf-8";"X-Auth-Token" = '"'+$TokenSet+'"'} -Method Get).content) | ConvertFrom-Json).flavors | where name -EQ "$Size").id
                    # Image
                    $ImageSet = (((Invoke-WebRequest -Uri https://lon.servers.api.rackspacecloud.com/v2/$Tenant/images -Method Get -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                    # Instance creation
                    $Body = '{"server": {"name": "'+$VMName+'","imageRef": "'+$ImageSet+'","flavorRef": "'+$sizeSet+'"}}'
                    Invoke-WebRequest -Uri https://lon.servers.api.rackspacecloud.com/v2/$Tenant/servers -Method Post -Headers @{"ContentType" = "application/json";"X-Auth-Token" = $TokenSet;"X-Auth-Project-Id" = $VMName} -Body $Body
                }
                "Remove" {}
                "Reboot" {}
                "Rebuild" {}
                default {}
            }
        }
        "DigitalOcean" {
            switch ($Action) {
                "Insert" {
                    # Image
                    $ImageSet = ((((((Invoke-WebRequest -Uri https://api.digitalocean.com/v2/images -Headers @{"Authorization" = "Bearer $Token"} -Method Get).content) | ConvertFrom-Json).images)| where slug -match "$Image").id)
                    # Region
                    $RegionSet = ((((((Invoke-WebRequest -Uri https://api.digitalocean.com/v2/regions -Headers @{"Authorization" = "Bearer $Token"} -Method Get).content) | ConvertFrom-Json).regions) | where available -Match "True" | where slug -match "$Region").slug)
                    # Size
                    $SizeSet = ((((((Invoke-WebRequest -Uri https://api.digitalocean.com/v2/sizes -Headers @{"Authorization" = "Bearer $Token"} -Method Get).content) | ConvertFrom-Json).sizes) | where available -Match "True" | where slug -match "$Size" ).slug)
                    # Instance creation
                    if ($Number -gt 1) {
                        switch ($Number) {
                                2 {$body = '{"name": ["'+$VMName[0]+'","'+$VMName[1]+'"],"region": "'+$RegionSet+'","size": "'+$SizeSet+'","image": "'+$ImageSet+'","ssh_keys": null,"backups": false,"ipv6": true,"user_data": null,"private_networking": null}'}
                                3 {$body = '{"name": ["'+$VMName[0]+'","'+$VMName[1]+'","'+$VMName[2]+'"],"region": "'+$RegionSet+'","size": "'+$SizeSet+'","image": "'+$ImageSet+'","ssh_keys": null,"backups": false,"ipv6": true,"user_data": null,"private_networking": null}'}
                                4 {$body = '{"name": ["'+$VMName[0]+'","'+$VMName[1]+'","'+$VMName[2]+'","'+$VMName[3]+'"],"region": "'+$RegionSet+'","size": "'+$SizeSet+'","image": "'+$ImageSet+'","ssh_keys": null,"backups": false,"ipv6": true,"user_data": null,"private_networking": null}'}
                                5 {$body = '{"name": ["'+$VMName[0]+'","'+$VMName[1]+'","'+$VMName[2]+'","'+$VMName[3]+'","'+$VMName[4]+'"],"region": "'+$RegionSet+'","size": "'+$SizeSet+'","image": "'+$ImageSet+'","ssh_keys": null,"backups": false,"ipv6": true,"user_data": null,"private_networking": null}'}
                                default {}
                            }
                        Invoke-WebRequest -Uri https://api.digitalocean.com/v2/droplets -Method POST -Headers @{"Content-Type" = "application/json";"Authorization" = "Bearer $Token"} -Body $body 
                        }
                    else {
                        $body = '{"name": "'+$VMName+'","region": "'+$RegionSet+'","size": "'+$SizeSet+'","image": "'+$ImageSet+'","ssh_keys": null,"backups": false,"ipv6": true,"user_data": null,"private_networking": null}'
                        Invoke-WebRequest -Uri https://api.digitalocean.com/v2/droplets -Method POST -Headers @{"Content-Type" = "application/json";"Authorization" = "Bearer $Token"} -Body $body
                        }
                    }
                "Remove" {
                    Invoke-WebRequest -Uri https://api.digitalocean.com/v2/droplets/$ServerId -Method Delete -Headers @{"Content-Type" = "application/json";"Authorization" = "Bearer $Token"}
                }
                "Reboot" {
                    Invoke-WebRequest -Uri https://api.digitalocean.com/v2/droplets/$ServerId/actions -Method Post -Headers @{"Content-Type" = "application/json";"Authorization" = "Bearer $Token"} -Body '{"type":"reboot"}'
                }
                "Rebuild" {
                    $ImageSet = ((((((Invoke-WebRequest -Uri https://api.digitalocean.com/v2/images -Headers @{"Authorization" = "Bearer $Token"} -Method Get).content) | ConvertFrom-Json).images)| where slug -match "$Image").id)
                    Invoke-WebRequest -Uri https://api.digitalocean.com/v2/droplets/$ServerId/actions -Method Post -Headers @{"Content-Type" = "application/json";"Authorization" = "Bearer $Token"} -Body '{"type":"rebuild","image":"'+$ImageSet+'"}'
                }
                default {}
            }
        }
        "Google" {
            switch ($Action) {
                "Insert" {
                    # Image
                    switch ($Image) {
                        "debian" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/debian-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        "centos" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/centos-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        "opensuse" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/opensuse-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        "red(-)hat" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/rhel-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        "ubuntu" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects$Project/ubuntu-os-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        "Windows" {
                            $ImageSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/windows-cloud/global/images -Headers @{"Authorization" = "Bearer " + $Token} -Method Get ).content | ConvertFrom-Json).items | where selfLink -Match "$Image" | select -Last 1)
                        }
                        default {}
                    }
                    # Region
                    $RegionSet = (((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/regions -Headers @{"Authorization" = "Bearer " + $Token} -Method Get).content | ConvertFrom-Json | where items -Match "$Region" ).SelfLink)
                    # Size
                    $SizeSet = ((Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/zones/$RegionSet/machineType -Method Get -Headers @{"Authorization" = "Bearer " + $Token}).content | ConvertFrom-Json | where name -Match $Size).selfLink
                    # Instance creation
                    $Body = '{
                        "name": "'+$VMName+'",
                        "machineType": "'+$SizeSet+'",
                        "networkInterfaces": 
                            [{"accessConfigs": 
                                [{"type": "ONE_TO_ONE_NAT","name": "External NAT"}],
                            "network": "global/networks/default"}],
                            "disks": 
                            [{"autoDelete": "true",
                                "boot": "true",
                                "type": "PERSISTENT",
                                "initializeParams": 
                                {"sourceImage": "'+$ImageSet+'"}
                            }]
                        }'
                    Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/zones/$Zone/instances -Method POST -Headers @{"ContentType" = "application/json";"Content-Type" = "application/x-www-form-urlencoded";"Authorization" = "Bearer " + $Token} -body $Body
                }
                "Remove" {
                    Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/zones/$Zone/instances/$ServerId -Method Delete -Headers @{"ContentType" = "application/json";"Content-Type" = "application/x-www-form-urlencoded";"Authorization" = "Bearer " + $Token}
                }
                "Reboot" {
                    Invoke-WebRequest -Uri https://www.googleapis.com/compute/v1/projects/$Project/zones/$Zone/instances/$ServerId/reset -Method Post -Headers @{"ContentType" = "application/json";"Content-Type" = "application/x-www-form-urlencoded";"Authorization" = "Bearer " + $Token}
                }
                default {}
            }
        }
        "Amazon" {
            switch ($Action) {
                "Insert" {
                    if ((Get-Command -ListAvailable) -notmatch "AWSPowerShell") {
                        Invoke-WebRequest -Uri "http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi" -Outfile "c:\AWSToolsAndSDKForNet.msi"
                        Install-MSIFile "c:\AWSToolsAndSDKForNet.msi"
                        Remove-Item "c:\AWSToolsAndSDKForNet.msi"
                    }
                    # KeyPair
                    $KeyPair = New-EC2KeyPair -KeyName KeyPair
                    $KeyPair.KeyMaterial | Out-File -Encoding ascii keypair.pem
                    # Images 
                    $date = [string]((Get-Date).Year)+"."+"0"+(((Get-Date).Month)-1)
                    switch ($Image) {
                        "Windows Server 2003" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.ImageLocation -match "amazon/windows_server-2003-R2_SP2-English-32Bit-Base-$date"} ).ImageId}
                        "Windows Server 2012" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.ImageLocation -match "amazon/windows_server-2012-R2_RTM-English-64Bit-Base-$date"} ).ImageId}
                        "Windows Server 2008" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.ImageLocation -match "amazon/Windows_Server-2008-SP2-English-32Bit-Base-$date"}).ImageId}
                        "CentOS" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.VirtualizationType -match "hvm"} | where {$_.ImageLocation -match "aws-marketplace/"} | where {$_.Name -match "CentOS Linux 7"} | select -Last 1).ImageId}
                        "Debian" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.VirtualizationType -match "hvm"} | where {$_.ImageLocation -match "aws-marketplace/"} | where {$_.Name -match "Debian"} | where {$_.CreationDate -match ((Get-Date).Year)} | select -Last 1).ImageId}
                        "Fedora" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.VirtualizationType -match "hvm"} | where {$_.ImageLocation -match "aws-marketplace/"} | where {$_.Name -match "fedora"} |select -Last 1).ImageId}
                        "Ubuntu" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.VirtualizationType -match "hvm"} | where {$_.ImageLocation -match "ubuntu-eu-central-1/images/hvm-instance/"} | where {$_.CreationDate -match ((Get-Date).Year)} | select -Last 1).ImageId}
                        "Gentoo" {$ImageSet = (Get-Ec2Image -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone | where {$_.VirtualizationType -match "hvm"} | where {$_.Name -match "gentoo-2016"} | select -Last 1).ImageId}
                        default {}
                    }
                    # EC2Type
                    switch ($EC2Type) {
                        "Classic" {
                            New-EC2SecurityGroup -GroupName "Security" -GroupDescription "EC2-Classic from PowerShell" -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone
                            $Group = (Get-EC2SecurityGroup -GroupNames "Security" -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone).GroupId
                            New-EC2Instance -ImageId $ImageSet -MinCount 1 -MaxCount $Number -KeyName $KeyPair -SecurityGroup $Group -InstanceType t1.micro -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone
                        }
                        "VPC" {
                            New-EC2SecurityGroup -GroupName "Security" -GroupDescription "EC2-VPC from PowerShell" -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone
                            $Group = (Get-EC2SecurityGroup -GroupNames "Security" -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone).GroupId
                            $ip1 = new-object Amazon.EC2.Model.IpPermission
                            $ip1.IpProtocol = "tcp"
                            $ip1.FromPort = 22
                            $ip1.ToPort = 22
                            $ip2 = new-object Amazon.EC2.Model.IpPermission
                            $ip2.IpProtocol = "tcp"
                            $ip2.FromPort = 3389
                            $ip2.ToPort = 3389
                            Grant-EC2SecurityGroupIngress -GroupId $Group -IpPermissions @($ip1, $ip2)
                            New-EC2Instance -ImageId $ImageSet -MinCount 1 -MaxCount $Number -KeyName $KeyPair -SecurityGroup $Group -InstanceType t1.micro -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone
                        }
                        default {}
                    }
                }
                "Remove" {
                    Stop-EC2Instance -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone -Instance $ServerId -Terminate -Force 
                }
                "Reboot" {
                    Restart-EC2Instance -AccessKey $AccessKey -SecretKey $SecretKey -Region $Zone -InstanceId $ServerId -Force
                }
                default {}
            }
        }
        default {}
    }
}