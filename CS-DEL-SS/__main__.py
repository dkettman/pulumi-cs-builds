import ipaddress
import json

import pulumi
from pulumi_azure_native import resources, network, compute
from pulumi_azure_native.network import (
    GetVirtualNetworkResult,
    get_virtual_network_output,
)

from typing import List

# Import the program's configuration settings
config = pulumi.Config()
stack = pulumi.get_stack()
svrs = json.loads(config.get("servers"))
imgs = json.loads(config.get("images"))
roles = json.loads(config.get("roles"))

# Set some variable (may need to goto config)
subnet_mask = 24
vnet_name = "vnet-CyberSolve-Labs"

# Locate the "rg-CyberSolve-Labs" resource group
resource_group = resources.get_resource_group(resource_group_name="rg-CyberSolve-Labs")

vnet_output: pulumi.Output[GetVirtualNetworkResult] = get_virtual_network_output(
    resource_group_name=resource_group.name, virtual_network_name=vnet_name
)

vnet = network.get_virtual_network(
    resource_group_name=resource_group.name, virtual_network_name=vnet_name
)


def get_resource_name(arg) -> str:
    #        subnet_name="CS-DEL-subnet-" + pulumi.get_stack(),
    return


def get_next_subnet_prefix(vnet: GetVirtualNetworkResult) -> str:
    if not vnet.address_space or not vnet.address_space.address_prefixes:
        raise ValueError("No address spaces found in the current VNet")

    vnet_address_space: ipaddress.IPv4Network | ipaddress.IPv6Network = (
        ipaddress.ip_network(address=vnet.address_space.address_prefixes[0])
    )
    possible_subnets = list(vnet_address_space.subnets(new_prefix=subnet_mask))

    occupied_address_spaces: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
        [
            ipaddress.ip_network(subnet.address_prefix)
            for subnet in vnet.subnets
            if subnet.address_prefix
        ]
        if vnet.subnets
        else []
    )

    pulumi.log.info(f"Vnet address space: {vnet_address_space}")
    pulumi.log.info(f"Occupied subnets: {occupied_address_spaces}")

    for subnet in possible_subnets:
        if not any(subnet.overlaps(occupied) for occupied in occupied_address_spaces):
            pulumi.log.info(f"First available /{subnet_mask} subnet: {str(subnet)}")
            return str(subnet)

    raise ValueError(
        "No available subnet prefixes found in the current VNet address space"
    )


subnet: network.Subnet
sub_info = None

try:
    sub_info = network.get_subnet(
        resource_group_name=resource_group.name,
        subnet_name="snet-" + pulumi.get_stack(),
        virtual_network_name=vnet_name,
    )
except:
    pass

subnet = network.Subnet(
    address_prefix=(
        sub_info.address_prefix
        if sub_info != None
        else vnet_output.apply(get_next_subnet_prefix)
    ),
    resource_name="snet-" + pulumi.get_stack(),
    resource_group_name=resource_group.name,
    subnet_name="snet-" + pulumi.get_stack(),
    virtual_network_name=vnet_name,
)

network_security_group = network.NetworkSecurityGroup(
    resource_name="nsg-" + pulumi.get_stack(),
    location=config.get("location", "EastUS2"),
    resource_group_name="rg-CyberSolve-Labs",
    network_security_group_name="nsg-" + pulumi.get_stack(),
    security_rules=[
        {
            "access": network.SecurityRuleAccess.ALLOW,
            "destination_address_prefix": "*",
            "destination_port_range": "3389",
            "direction": network.SecurityRuleDirection.INBOUND,
            "name": "RDP-Inbound",
            "priority": 130,
            "protocol": network.SecurityRuleProtocol.ASTERISK,
            "source_address_prefix": "*",
            "source_port_range": "*",
        }
    ],
    tags={
        "Owner": config.get("Owner"),
        "Email": config.get("Email"),
    },
)


def build_computer_resource(
    vm_name: str, vm_type: str, vm_extras: List[str], vm_image: dict
) -> compute.VirtualMachineArgs:

    pip_config = None

    # Check for Extras
    if "PIP" in vm_extras:
        print("Configuring PIP!")
        pip_config = network.PublicIPAddress(
            "pip-" + vm_name + "-" + pulumi.get_stack(),
            resource_group_name=resource_group.name,
            public_ip_allocation_method="Static",
            location=config.get("location"),
            tags={
                "Owner": config.get("Owner"),
                "Email": config.get("Email"),
            },
        )

    # Build the NIC
    nic = network.NetworkInterface(
        resource_name="nic-" + vm_name + "-" + pulumi.get_stack(),
        resource_group_name=resource_group.name,
        ip_configurations=[
            network.NetworkInterfaceIPConfigurationArgs(
                name="ipConfig",
                subnet=network.SubnetArgs(id=subnet.id),
                private_ip_allocation_method="Dynamic",
                public_ip_address=(
                    network.PublicIPAddressArgs(id=pip_config.id)
                    if pip_config
                    else None
                ),
            ),
        ],
        tags={
            "Owner": config.get("Owner"),
            "Email": config.get("Email"),
        },
    )

    # Build the Virtual Machine Object from assembled parts
    vm_args = compute.VirtualMachineArgs(
        resource_group_name=resource_group.name,
        diagnostics_profile=compute.DiagnosticsProfileArgs(
            boot_diagnostics=compute.BootDiagnosticsArgs(enabled=True)
        ),
        hardware_profile=compute.HardwareProfileArgs(vm_size=roles[vm_type]["vmSize"]),
        network_profile=compute.NetworkProfileArgs(
            network_interfaces=[
                compute.NetworkInterfaceReferenceArgs(id=nic.id, primary=True)
            ]
        ),
        os_profile=compute.OSProfileArgs(
            admin_password=config.get("adminPassword"),
            admin_username=config.get("adminUsername"),
            computer_name=vm_name,
        ),
        storage_profile={
            "image_reference": imgs[roles[vm_type]["osImage"]],
            "os_disk": {
                "caching": compute.CachingTypes.READ_WRITE,
                "create_option": compute.DiskCreateOptionTypes.FROM_IMAGE,
                "delete_option": "Delete",
                "managed_disk": {
                    "storage_account_type": compute.StorageAccountTypes.STANDARD_LRS,
                },
                "name": "osDisk-" + vm_name + "-" + pulumi.get_stack(),
            },
        },
        vm_name="vm-" + vm_name + "-" + pulumi.get_stack(),
        tags={
            "Owner": config.get("Owner"),
            "Email": config.get("Email"),
            "Extras": roles[s]["extras"],
        },
    )
    vm = compute.VirtualMachine(
        resource_name="vm-" + vm_name + "-" + pulumi.get_stack(),
        args=vm_args,
    )


#     vm_dsc = compute.VirtualMachineRunCommandByVirtualMachine(
#         "CS-DEL-vmdsc-" + vm_name + "-" + pulumi.get_stack(),
#         resource_group_name=resource_group.name,
#         vm_name=vm.name,
#         source=compute.VirtualMachineRunCommandScriptSourceArgs(
#             # script="type NUL > C:\\test.txt"
#             script="""
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
# Install-Module ActiveDirectoryDSC -Force;

# Configuration makeDomain {
#     Import-DscResource -ModuleName PSDesiredStateConfiguration ;
#     Import-DscResource -ModuleName ActiveDirectoryDSC ;

#     $username = "cs_admin";
#     $password = "Cyb3rS0lve!!";

#     # Convert the password string to a secure string
#     $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force;

#     # Create the PSCredential object
#     $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePassword;

#     Node 'localhost' {
#         WindowsFeature 'ADDS'
#         {
#             Name = 'AD-Domain-Services'
#             Ensure = 'Present'
#             IncludeAllSubFeature = $True
#         }

#         ADDomain 'spslab.local'
#         {
#             DomainName = 'spslab.local'
#             Credential = $Credential
#             SafemodeAdministratorPassword = $Credential
#             ForestMode = 'WinThreshold'
#         }
#     }
# }

# $cd = @{
#     AllNodes = @(
#         @{
#             NodeName = 'localhost'
#             PSDscAllowDomainUser = $true
#             PSDscAllowPlainTextPassword = $true
#         }
#     )
# }

# makeDomain -OutputPath 'C:\\DSC' -ConfigurationData $cd

# Start-DscConfiguration 'C:\\DSC' -Wait -Verbose
# """
#         ),
#     )

#     pass


# build_computer_resource(
#     # "foo", "DC", ["PIP", "AD", "CS", "ADTools", "SQL", "RMQ"], "foo"
#     "foo",
#     "DC",
#     ["AD", "CS", "ADTools", "SQL", "RMQ"],
#     "foo",
# )

for s in svrs:
    # print(svrs[s]["vmName"], s, roles[s]["extras"], imgs[roles[s]["osImage"]])
    build_computer_resource(
        svrs[s]["vmName"], s, roles[s]["extras"], imgs[roles[s]["osImage"]]
    )
