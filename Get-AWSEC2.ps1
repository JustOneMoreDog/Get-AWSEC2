function Expand-Property {

    [CmdletBinding(SupportsShouldProcess)][Alias('exp')]Param(
        [Parameter(ValueFromPipeline)]$Input,
        [Parameter(Mandatory, Position=0)][String]$Property
    )
    process {
        try {
            $Input | Select-Object -ExpandProperty $Property 
        } catch {
            $Input
            Write-Error -ErrorAction STOP -Message $PSItem.exception.message
        }
    }
}

<#
    .SYNOPSIS
    Maps the properties of different EC2 resources to the properties of other EC2 resources

    .DESCRIPTION
    Creates a custom powershell object that holds ArrayLists of filled out resources for each supported type of resource

    .PARAMETER Instances
    A list of instances to be used in the mapping. Default will call Get-EC2Instance

    .PARAMETER Snapshots
    A list of instances to be used in the mapping. Default will call Get-EC2Snapshot -OwnerId self
    
    .PARAMETER AMI
    A list of AMI to be used in the mapping. Default will call Get-EC2Image -Owner self
    
    .PARAMETER SecurityGroups
    A list of security groups to be used in the mapping. Default will call Get-EC2SecurityGroup
    
    .PARAMETER Subnets
    A list of subnets to be used in the mapping. Default will call Get-EC2Subnet
    
    .PARAMETER VPC
    A list of VPCs to be used in the mapping. Default will call Get-EC2Vpc
    
    .PARAMETER KeyPairs
    A list of key pairs to be used in the mapping. Default will call Get-EC2KeyPair

    .PARAMETER IAM
    A list of IAM instances to be used in the mapping. Default will call Get-IAMInstanceProfileList

    .PARAMETER DHCP
    A list of DHCP options to be used in the mapping. Default will call Get-EC2DhcpOption

    .PARAMETER Volumes
    A list of volumes to be used in the mapping. Default will call Get-EC2Volume

    .PARAMETER v
    Will turn on detailed output. Default is off

    .PARAMETER NoProgress
    Will completely turn off any verbose messages saying where the script is at. Default is on

    .OUTPUTS
    System.Management.Automation.PSCustomObject. Object that contains a series of ArrayLists

    .EXAMPLE
    $masterObj = Get-AWSEC2 -v

    .EXAMPLE
    $masterObj = Get-AWSEC2 -Instances $instances

    .LINK
    https://github.com/picnicsecurity/
#>
function Get-AWSEC2 {
    Param(
        [Parameter(Mandatory=$false)]$Instances          = $(Get-EC2Instance),
        [Parameter(Mandatory=$false)]$Snapshots          = $(Get-EC2Snapshot -OwnerId self),
        [Parameter(Mandatory=$false)]$AMIs               = $(Get-EC2Image -Owner self),
        [Parameter(Mandatory=$false)]$SecurityGroups     = $(Get-EC2SecurityGroup),
        [Parameter(Mandatory=$false)]$Subnets            = $(Get-EC2Subnet),
        [Parameter(Mandatory=$false)]$VPC                = $(Get-EC2Vpc),
        [Parameter(Mandatory=$false)]$KeyPairs           = $(Get-EC2KeyPair),
        [Parameter(Mandatory=$false)]$IamInstances       = $(Get-IAMInstanceProfileList),
        [Parameter(Mandatory=$false)]$DHCP               = $(Get-EC2DhcpOption),
        [Parameter(Mandatory=$false)]$Volumes            = $(Get-EC2Volume),
        [Parameter(Mandatory=$false)][Switch]$NoProgress = $true,
        [Parameter(Mandatory=$false)][Switch]$v          = $false    
    )

    if($v){
        $Global:VerbosePreference = 'Continue'
        Write-Verbose "Verbosity turned on"
    } else {
        $Global:VerbosePreference = 'SilentlyContinue'
    }


    <# FORMATTED RESOURCES #>
    # We are doing it this way so that when the function returns the masterObj we do not loose the references to these objects
    # Eventually we should change these to be generic lists of the objects that they contain ie New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.InstanceBlockDeviceMapping]'
    Write-Verbose "Building Formatted Resources"
    $Global:masterObj = [pscustomobject][ordered]@{
        "Instances"      = [System.Collections.ArrayList]@()
        "Snapshots"      = [System.Collections.ArrayList]@()
        "Volumes"        = [System.Collections.ArrayList]@()
        "AMI"            = [System.Collections.ArrayList]@() 
        "SecurityGroups" = [System.Collections.ArrayList]@()
        "IAM"            = [System.Collections.ArrayList]@()
        "VPC"            = [System.Collections.ArrayList]@()
        "DHCPOptions"    = [System.Collections.ArrayList]@()
        "Subnets"        = [System.Collections.ArrayList]@()
        "KeyPairs"       = [System.Collections.ArrayList]@()
        "UnknownIDs"     = [System.Collections.ArrayList]@()
        "DNEResources"   = [pscustomobject][ordered]@{
            "Instances"      = [System.Collections.ArrayList]@()
            "Snapshots"      = [System.Collections.ArrayList]@()
            "Volumes"        = [System.Collections.ArrayList]@()
            "AMI"            = [System.Collections.ArrayList]@() 
            "SecurityGroups" = [System.Collections.ArrayList]@()
            "IAM"            = [System.Collections.ArrayList]@()
            "VPC"            = [System.Collections.ArrayList]@()
            "DHCPOptions"    = [System.Collections.ArrayList]@()
            "Subnets"        = [System.Collections.ArrayList]@()
            "KeyPairs"       = [System.Collections.ArrayList]@()
        }
    }
    # Filled Out Resources
    $filledOutInstances = $masterObj.Instances
    $filledOutSnapshots = $masterObj.Snapshots
    $filledOutAMIs      = $masterObj.AMI
    $filledOutSecGroups = $masterObj.SecurityGroups
    $filledOutVolumes   = $masterObj.Volumes
    $filledOutSubnets   = $masterObj.Subnets
    $filledOutKeyPairs  = $masterObj.KeyPairs
    $filledOutDhcp      = $masterObj.DHCPOptions
    $filledOutVpc       = $masterObj.VPC
    $filledOutIam       = $masterObj.IAM
    # DNE Resources
    $dneInstances = $masterObj.DNEResources.Instances 
    $dneSnapshots = $masterObj.DNEResources.Snapshots
    $dneAMIs      = $masterObj.DNEResources.AMI
    $dneSecGroups = $masterObj.DNEResources.SecurityGroups
    $dneVolumes   = $masterObj.DNEResources.Volumes
    $dneSubnets   = $masterObj.DNEResources.Subnets
    $dneKeyPairs  = $masterObj.DNEResources.KeyPairs
    $dneDhcp      = $masterObj.DNEResources.DHCPOptions
    $dneVpc       = $masterObj.DNEResources.VPC
    $dneIam       = $masterObj.DNEResources.IAM
    <# /FORMATTED RESOURCES #>

    <# DEBUGGING VARIABLES #>
    $unknownIds = $masterObj.UnknownIDs
    <# /DEBUGGING VARIABLES #>

    <# INNER FUNCTIONS #>
    Write-Verbose "Building inner functions"
    
    # DONE DONE DONE
    function Get-SecurityGroups {
        param($SecurityGroupId,$SecurityGroupName,[switch]$Reference)

        if($Reference){
            Write-Verbose "Getting reference for $SecurityGroupId"
            $secGroupObj = Confirm-Resource -FilledOutList $filledOutSecGroups -MasterList $securityGroups -DNEList $dneSecGroups -ResourceID $SecurityGroupId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$secGroupObj){
                Write-Verbose "Making DNE Security Group object for $SecurityGroupId"
                $secGroupObj = [Amazon.EC2.Model.SecurityGroup]::new()
                $secGroupObj.GroupId = $SecurityGroupId
                $secGroupObj.GroupName = $SecurityGroupName
                $secGroupObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $SecurityGroupId
                $secGroupObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                # Making sure that we return a reference
                $index = $dneSecGroups.Add($secGroupObj)
                return $dneSecGroups[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$secGroupObj.ResourceID){
                    Write-Verbose "Building filled out Security Group object skeleton for $SecurityGroupId"
                    $secGroupFilledObj = [Amazon.EC2.Model.SecurityGroup]::new()
                    $secGroupFilledObj.GroupId = $SecurityGroupId
                    $secGroupFilledObj.GroupName = $SecurityGroupName
                    $vpcObj = Get-VPC -Reference -vpcId $($secGroupObj.VpcId)
                    $secGroupFilledObj | Add-Member -MemberType NoteProperty -Name "VpcId" -Value $vpcObj -Force
                    $secGroupFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $SecurityGroupId
                    $secGroupFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    # Making sure that we return a reference
                    $index = $filledOutSecGroups.Add($secGroupFilledObj)
                    return $filledOutSecGroups[$index]
                } else {
                    return $secGroupObj
                }
            }
        } else {
            Write-Verbose "Filling out new security group object for $secGroupId"                
            $secObj = $filledOutSecGroups | Where-Object { $_.GroupId -eq $secGroupId }
            if(!$secObj){
                Write-Verbose "No filled out Security Group object has been made yet for $secGroupId"
                # Instead of copying code down here we can just call this function again
                $secObj = Get-SecurityGroups -Reference -SecurityGroupId $SecurityGroupId -SecurityGroupName $SecurityGroupName
            }
            $secMasterObj = $securityGroups | Where-Object { $_.GroupId -eq $secGroupId }
            Write-Verbose "Filling out Security Group object for $secGroupId"
            $($secMasterObj).PSObject.Properties | ForEach-Object {
                if($_.Name -eq "VpcId"){
                    continue
                } else {  
                    $secObj."$($_.Name)" = $_.Value
                }
            }
        }
        return $null
    }


    # DONE DONE DONE
    function Get-Subnet {
        param($subnetId,[switch]$Reference)

        if($Reference){
            Write-Verbose "Getting reference for $subnetId"
            $subnetObj = Confirm-Resource -FilledOutList $filledOutSubnets -MasterList $subnets -DNEList $dnesubnets -ResourceID $subnetId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$subnetObj){
                Write-Verbose "Making DNE Subnet object for $subnetId"
                $subnetObj = [Amazon.EC2.Model.Subnet]::new()
                $subnetObj.SubnetId = $subnetId
                $subnetObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $subnetId
                $subnetObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dnesubnets.Add($subnetObj)
                # Making sure that we return a reference
                return $dnesubnets[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$subnetObj.ResourceID){
                    Write-Verbose "Building filled out Subnet object skeleton for $subnetId"
                    $subnetFilledObj = [Amazon.EC2.Model.Subnet]::new()
                    Write-Verbose "$subnetId is calling Get-VPC with $($subnetObj.VpcId)"
                    $vpcObj = Get-VPC -Reference -vpcId $($subnetObj.VpcId)
                    $subnetFilledObj | Add-Member -MemberType NoteProperty -Name "VpcId" -Value $vpcObj -Force
                    $subnetFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $subnetId
                    $subnetFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutSubnets.Add($subnetFilledObj)
                    return $filledOutSubnets[$index]
                } else {
                    return $subnetObj
                }
            }
        } else { 
            $subnetObj = $filledOutSubnets | Where-Object { $_.SubnetId -eq $subnetId }
            if(!$subnetObj){
                Write-Verbose "No filled out Subnet object has been made yet for $subnetId"
                # Instead of copying code down here we can just call this function again
                $subnetObj = Get-Subnet -Reference -subnetId $subnetId
            }
            $subnetMasterObj = $subnets | Where-Object { $_.DhcpOptionsId -eq $subnetId }
            Write-Verbose "Filling out Subnet object for $subnetId"
            $($subnetMasterObj).PSObject.Properties | ForEach-Object {
                if($_.Name -eq "VpcId"){
                    continue
                }  
                $subnetObj."$($_.Name)" = $_.Value
            }    
        }
        return $null
    }

    # DONE DONE DONE
    function Get-KeyPair {
        param($keyName,[switch]$Reference)

        if($Reference){
            Write-Verbose "Getting reference for $keyName"
            $keyObj = Confirm-Resource -FilledOutList $filledOutKeyPairs -MasterList $keyPairs -DNEList $dneKeyPairs -ResourceID $keyName
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$keyObj){
                Write-Verbose "Making DNE Key Pair object for $keyName"
                $keyObj = [Amazon.EC2.Model.KeyPairInfo]::new()
                $keyObj.KeyName = $keyName
                $keyObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $keyName
                $keyObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneKeyPairs.Add($keyObj)
                # Making sure that we return a reference
                return $dneKeyPairs[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$keyObj.ResourceID){
                    Write-Verbose "Building filled out Key Pair object skeleton for $keyName"
                    $keyFilledObj = [Amazon.EC2.Model.KeyPairInfo]::new()
                    $keyFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $keyName
                    $keyFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutKeyPairs.Add($keyFilledObj)
                    # Making sure that we return a reference
                    return $filledOutKeyPairs[$index]
                } else {
                    return $keyObj
                }
            }
        } else { 
            $keyObj = $filledOutKeyPairs | Where-Object { $_.VpcId -eq $keyName }
            if(!$keyObj){
                Write-Verbose "No filled out VPC object has been made yet for $keyName"
                # Instead of copying code down here we can just call this function again
                $keyObj = Get-KeyPair -Reference -keyName $keyName
            }
            $keyMasterObj = $keyPairs | Where-Object { $_.DhcpOptionsId -eq $keyName }
            Write-Verbose "Filling out VPC object for $keyName"
            $($keyMasterObj).PSObject.Properties | ForEach-Object {  
                $keyObj."$($_.Name)" = $_.Value
            }    
        }
        return $true
    }

    # DONE DONE DONE
    function Get-DHCP {
        param($DhcpId,[switch]$Reference)

        # Unless we working DHCP specifically then we all we want to hand out is a skeleton. This prevents any loop situations (see volume <-> snapshot)
        if($Reference){
            $dhcpObj = Confirm-Resource -FilledOutList $filledOutDhcp -MasterList $DHCP -DNEList $dneDhcp -ResourceID $DhcpId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$dhcpObj){
                Write-Verbose "Making DNE DHCP object for $DhcpId"
                $dhcpObj = [Amazon.EC2.Model.DhcpOptions]::new()
                $dhcpObj.DhcpOptionsId = $DhcpId
                $dhcpObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $DhcpId
                $dhcpObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneDhcp.Add($dhcpObj)
                # Making sure that we return a reference
                return $dneDhcp[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$dhcpObj.ResourceID){
                    Write-Verbose "Building filled out DHCP object skeleton for $DhcpId"
                    $dhcpFilledObj = [Amazon.EC2.Model.DhcpOptions]::new()
                    $dhcpFilledObj.DhcpOptionsId = $DhcpId
                    $dhcpFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $DhcpId
                    $dhcpFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutDhcp.Add($dhcpFilledObj)
                    # Making sure that we return a reference
                    return $filledOutDhcp[$index]
                } else {
                    return $dhcpObj
                }
            }
        } else {
            $dhcpObj = $filledOutDhcp | Where-Object { $_.DhcpOptionsId -eq $DhcpId }
            if(!$dhcpObj){
                Write-Verbose "No filled out DHCP object has been made yet for $DhcpId"
                # Instead of copying code down here we can just call this function again
                $dhcpObj = Get-DHCP -Reference -DhcpId $DhcpId
            }
            $dhcpMasterObj = $DHCP | Where-Object { $_.DhcpOptionsId -eq $DhcpId }
            Write-Verbose "Filling out DHCP object for $DhcpId"
            $($dhcpMasterObj).PSObject.Properties | ForEach-Object {  
                $dhcpObj."$($_.Name)" = $_.Value
            }
        }
        return $null
    }

    # DONE DONE DONE
    function Get-VPC {
        param($vpcId,[switch]$Reference)

        if($Reference){
            Write-Verbose "Getting reference for $vpcId"
            $vpcObj = Confirm-Resource -FilledOutList $filledOutVpc -MasterList $VPC -DNEList $dneVpc -ResourceID $vpcId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$vpcObj){
                Write-Verbose "Making DNE DHCP object for $vpcId"
                $vpcObj = [Amazon.EC2.Model.Vpc]::new()
                $vpcObj.VpcId = $vpcId
                $vpcObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $vpcId
                $vpcObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneVpc.Add($vpcObj)
                # Making sure that we return a reference
                return $dneVpc[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$vpcObj.ResourceID){
                    Write-Verbose "Building filled out VPC object skeleton for $vpcId"
                    $vpcFilledObj = [Amazon.EC2.Model.Vpc]::new()
                    $dhcpObj = Get-DHCP -Reference $($vpcObj.DhcpOptionsId) 
                    $vpcFilledObj | Add-Member -MemberType NoteProperty -Name "DhcpOptionsId" -Value $dhcpObj -Force
                    $vpcFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $vpcId
                    $vpcFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutVpc.Add($vpcFilledObj)
                    # Making sure that we return a reference
                    return $filledOutVpc[$index]
                } else {
                    return $vpcObj
                }
            }
        } else {
            $vpcObj = $filledOutVpc | Where-Object { $_.VpcId -eq $vpcId }
            if(!$vpcObj){
                Write-Verbose "No filled out VPC object has been made yet for $vpcId"
                # Instead of copying code down here we can just call this function again
                $vpcObj = Get-VPC -Reference -vpcId $vpcId
            }
            $vpcMasterObj = $VPC | Where-Object { $_.VpcId -eq $vpcId }
            Write-Verbose "Filling out VPC object for $vpcId"
            $($vpcMasterObj).PSObject.Properties | ForEach-Object {  
                if($_.Name -eq "DhcpOptionsId"){
                    Write-Verbose "$vpcId is skipping DHCP Options ID since its already filled out"
                    # Do Nothing
                } else {
                    $vpcObj."$($_.Name)" = $_.Value
                }
            }
        }
    }

    # DONE DONE DONE
    function Get-IAM {
        param($IamId, $IamArn, [switch]$Reference)

        if($Reference){
            $iamObj = Confirm-Resource -FilledOutList $filledOutIam -MasterList $iamInstances -DNEList $dneIam -ResourceID $IamId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$iamObj){
                Write-Verbose "Making DNE IAM Instance object for $IamId"
                $iamObj = [Amazon.IdentityManagement.Model.InstanceProfile]::new()
                $iamObj.InstanceProfileId = $IamId
                $iamObj.Arn = $IamArn
                $iamObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $IamId
                $iamObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneIam.Add($iamObj)
                # Making sure that we return a reference
                return $dneDhcp[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$iamObj.ResourceID){
                    Write-Verbose "Building filled out IAM Instance object skeleton for $IamId"
                    $iamFilledObj = [Amazon.IdentityManagement.Model.InstanceProfile]::new()
                    $iamFilledObj.InstanceProfileId = $IamId
                    $iamFilledObj.Arn = $IamArn
                    $iamFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $IamId
                    $iamFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutIam.Add($iamFilledObj)
                    # Making sure that we return a reference
                    return $filledOutIam[$index]
                } else {
                    return $iamObj
                }
            }
        } else {
            $iamObj = $filledOutIam | Where-Object { $_.InstanceProfileId -eq $IamId }
            if(!$iamObj){
                Write-Verbose "No filled out IAM Instance object has been made yet for $IamId"
                # Instead of copying code down here we can just call this function again
                $iamObj = Get-IAM -Reference -IamId $IamId -IamArn $IamArn
            }
            $iamMasterObj = $iamInstances | Where-Object { $_.InstanceProfileId -eq $IamId }
            Write-Verbose "Filling out IAM Instance object for $IamId"
            $($iamMasterObj).PSObject.Properties | ForEach-Object {  
                $iamObj."$($_.Name)" = $_.Value
            }
        }
        return $null
    }

    # DONE DONE DONE
    function Get-AMI {
        param($ImageId,[switch]$Reference)

        if($Reference){
            $amiObj = Confirm-Resource -FilledOutList $filledOutAMIs -MasterList $AMIs -DNEList $dneAMIs -ResourceID $ImageId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$amiObj){
                Write-Verbose "Making DNE AMI object for $ImageId"
                $amiObj = [Amazon.EC2.Model.Image]::new()
                $amiObj.ImageId = $ImageId
                $amiObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $ImageId
                $amiObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneAMIs.Add($amiObj)
                # Making sure that we return a reference
                return $dneAMIs[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$amiObj.ResourceID){
                    # We are filling out the AMI object in the reference block because too many of its property values connect over to other resource properties
                    Write-Verbose "Building filled out AMI object for $ImageId"
                    $amiFilledObj = [Amazon.EC2.Model.Image]::new()
                    $amiFilledObj.ImageId = $ImageId
                    $amiFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $ImageId
                    $amiFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    # To prevent loops we are going to add this object to the filled out ami list before doing anything further
                    $index = $filledOutAMIs.Add($amiFilledObj)
                    # Now we can call functions like Convert-TextToObject safely
                    foreach($property in $($amiObj.PSObject.Properties)){
                        Switch ($property.Name) {
                            "BlockDeviceMappings" {
                                Write-Verbose "$ImageId is calling Get-BlockDeviceMappings"
                                $blockDeviceMapObj = Get-BlockDeviceMappings -BlockDeviceMappings $property.Value -ResourceID $ImageId
                                $amiFilledObj.$_ = $blockDeviceMapObj
                                break
                            }
                            "CreationDate" {
                                if($property.Value){
                                    $creationTime = Get-Date $property.Value
                                } else {
                                    $creationTime = $property.Value    
                                }
                                $amiFilledObj.$_ = $creationTime
                                break
                            }
                            "Description" {
                                $Regex = [Regex]::new("((i)|(ami)|(vol))-([a-zA-Z0-9]{17}|[a-zA-Z0-9]{8})")
                                $text = $($property.Value)
                                if($text){
                                    $text = $text.ToLower()
                                } else {
                                    $text = ''
                                }
                                $descriptObj = Convert-TextToObject -Text $text -Regex $Regex -Title $_
                                $amiFilledObj.$_ = $descriptObj
                                break
                            }
                            "ImageLocation" {
                                $Regex = [Regex]::new("((i)|(ami)|(vol))-([a-zA-Z0-9]{17}|[a-zA-Z0-9]{8})")
                                $text = $($property.Value)
                                if($text){
                                    $text = $text.ToLower()
                                } else {
                                    $text = ''
                                }
                                $textObj = Convert-TextToObject -Text $text -Regex $Regex -Title $_
                                $amiFilledObj.$_ = $textObj
                                break
                            } 
                            "Name" {
                                $Regex = [Regex]::new("((i)|(ami)|(vol))-([a-zA-Z0-9]{17}|[a-zA-Z0-9]{8})")
                                $text = $($property.Value)
                                if($text){
                                    $text = $text.ToLower()
                                } else {
                                    $text = ''
                                }
                                $textObj = Convert-TextToObject -Text $text -Regex $Regex -Title $_
                                $amiFilledObj.$_ = $textObj
                                break
                            } 
                            default {
                                $amiFilledObj.$_ = $property.Value
                                break
                            }     
                        }
                    }
                    # Making sure that we return a reference
                    return $filledOutAMIs[$index]
                } else {
                    return $amiObj
                }
            }
        } else {
            $amiObj = $filledOutAMIs | Where-Object { $_.ImageId -eq $ImageId }
            if(!$amiObj){
                Write-Verbose "No filled out AMI object has been made yet for $amiObj"
                # Instead of copying code down here we can just call this function again
                $amiObj = Get-AMI -Reference -ImageId $ImageId
                # Unlike most of these functions, the reference block is filling out the object so we have nothing else to do here 
            }
        }
        return $null
    }

    # DONE DONE DONE 
    function Get-Volume {
        param(
            $VolumeID,
            [switch]$Reference
        )

        if($Reference){
            $volObj = Confirm-Resource -FilledOutList $filledOutVolumes -MasterList $Volumes -DNEList $dneVolumes -ResourceID $VolumeID
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$volObj){
                Write-Verbose "Making DNE Volume object for $VolumeID"
                $volObj = [Amazon.EC2.Model.Volume]::new()
                $volObj.SnapshotId = $SnapshotID
                $volObj.VolumeId = $VolumeID
                $volObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $VolumeID
                $volObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneVolumes.Add($volObj)
                # Making sure that we return a reference
                return $dneVolumes[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$volObj.ResourceID){
                    Write-Verbose "Filling out new volume object found for $VolumeID"
                    $volFilledObj = [Amazon.EC2.Model.Volume]::new()
                    $volFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceId" -Value $VolumeID
                    $volFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutVolumes.Add($volFilledObj)
                    $($volObj).PSObject.Properties | ForEach-Object {  
                        if($_.Name -eq "Attachments"){
                            # A volume can have more than 1 attachment so we just loop over each one and fill it out accordingly
                            $attachmentsList = [System.Collections.ArrayList]@()
                            foreach($attachment in $_.Value){
                                $attachmentObj = [Amazon.EC2.Model.VolumeAttachment]::new()
                                foreach($property in $($attachment.PSObject.Properties)){
                                    if($property.Name -eq "InstanceId"){
                                        $instanceId = $property.Value
                                        Write-Verbose "$VolumeID in Attachments is calling Get-Instance on $instanceID"
                                        $inst = Get-Instance -Reference -InstanceID $instanceId
                                        $attachmentObj | Add-Member -MemberType NoteProperty -Name "InstanceId" -Value $inst -Force
                                    }
                                    elseif($property.Name -eq "AttachTime"){
                                        $attachTime = Get-Date $property.Value
                                        $attachmentObj."AttachTime" = $attachTime
                                    } elseif($property.Name -eq "VolumeId"){
                                        # Should have just renamed this to ".." instead of "VolumeId" because that honestly makes more sense
                                        $attachmentObj | Add-Member -MemberType NoteProperty -Name "VolumeId" -Value $filledOutVolumes[$index] -Force   
                                    } else {
                                        $attachmentObj."$($property.Name)" = $property.Value    
                                    }
                                }
                                $attachmentsList.Add($attachmentObj) | Out-Null
                            }
                            $volFilledObj | Add-Member -MemberType NoteProperty -Name "Attachments" -Value $attachmentsList -Force
                        } 
                        elseif($_.Name -eq "CreateTime"){
                            $createTime = Get-Date $_.Value
                            $volFilledObj."$($_.Name)" = $createTime   
                        } 
                        elseif($_.Name -eq "SnapshotId"){
                            $snapId = $_.Value
                            if($snapId -match "^snap-.*"){
                                Write-Verbose "$VolumeID is calling Get-Snapshot on $snapId"
                                $snapObj = Get-Snapshot -Reference -SnapshotID $snapId -VolumeID $VolumeID
                                $volFilledObj | Add-Member -MemberType NoteProperty -Name $_ -Value $snapObj -Force
                            } else {
                                $volFilledObj."$($_.Name)" = $_.Value   
                            }   
                        } else {
                            $volFilledObj."$($_.Name)" = $_.Value
                        }
                    }
                    return $filledOutVolumes[$index]
                } else {
                    return $volObj
                }
            }
        } else {
            $volObj = $filledOutVolumes | Where-Object { $_.VolumeId -eq $VolumeID }
            if(!$volObj){
                Write-Verbose "No filled out Volume object has been made yet for $VolumeID"
                # Instead of copying code down here we can just call this function again
                $volObj = Get-Volume -Reference -VolumeID $VolumeID
            }
        }        
        return $null
    }

    # DONE DONE DONE 
    function Get-Snapshot {
        param(
            $SnapshotId,
            [switch]$Reference
        )

        # Amazon.EC2.Model.Snapshot

        if($Reference){
            $snapObj = Confirm-Resource -FilledOutList $filledOutSnapshots -MasterList $snapshots -DNEList $dneSnapshots -ResourceID $SnapshotId
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$snapObj){
                Write-Verbose "Making DNE Snapshot object for $SnapshotId"
                $snapObj = [Amazon.EC2.Model.Snapshot]::new()
                $snapObj.SnapshotId = $SnapshotId
                $snapObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $SnapshotId
                $snapObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false
                $index = $dneSnapshots.Add($snapObj)
                # Making sure that we return a reference
                return $dneSnapshots[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$snapObj.ResourceID){
                    Write-Verbose "Building filled out Snapshot object for $SnapshotId"
                    $snapFilledObj = [Amazon.EC2.Model.Snapshot]::new()
                    $snapFilledObj.SnapshotId = $SnapshotId
                    $snapFilledObj | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $SnapshotId
                    $snapFilledObj | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $index = $filledOutSnapshots.Add($snapFilledObj)

                    foreach($property in $($obj.PSObject.Properties)){
                        Switch ($property.Name) {
                            "Description" {
                                $Regex = [Regex]::new("((i)|(ami)|(vol))-([a-zA-Z0-9]{17}|[a-zA-Z0-9]{8})")
                                $text = $($property.Value)
                                if($text){
                                    $text = $text.ToLower()
                                } else {
                                    $text = ''
                                }
                                $descriptObj = Convert-TextToObject -Text $text -Regex $Regex -Title $_
                                $snapFilledObj | Add-Member -MemberType NoteProperty -Name $_ -Value $descriptObj -Force
                                break
                            }
                            "StartTime" {
                                if($property.Value){
                                    $startTime = Get-Date $property.Value
                                } else {
                                    $startTime = $property.Value    
                                }
                                $snapFilledObj.$_ = $startTime
                                break
                            } 
                            "VolumeId" {
                                $volId = $property.Value
                                $volObj = Get-Volume -Reference -VolumeID $volId
                                $snapFilledObj | Add-Member -MemberType NoteProperty -Name $_ -Value $volObj -Force
                                break
                            }
                            default {
                                $snapFilledObj | Add-Member -MemberType NoteProperty -Name $_ -Value $property.Value
                                break
                            }     
                        }
                    }
                    # Making sure that we return a reference
                    return $filledOutSnapshots[$index]
                } else {
                    return $snapObj
                }
            }
        } else {
            $snapObj = $filledOutSnapshots | Where-Object { $_.SnapshotId -eq $SnapshotId }
            if(!$snapObj){
                Write-Verbose "No filled out Snapshot object has been made yet for $SnapshotId"
                # Same situation as volume and AMI
                $snapObj = Get-Snapshot -Reference -SnapshotId $SnapshotId
            }
        }
        return $null
    }

    # DDDDDDDDDDDOOOOOOOOONNNNNNNNNNNNEEEEEEEEEEEE 
    function Get-Instance {
        param($InstanceID, [switch]$Reference)

        #$inst = $filledOutInstances | exp Instances | Where-Object { $_.InstanceID -eq $InstanceID }
        if($Reference){
            $instance = Confirm-Resource -FilledOutList $filledoutinstances -MasterList $instances -DNEList $dneInstances -ResourceID $InstanceID
            # If Confirm-Resource returns false then we need to make a dead reference object and add it to our DNE List
            if(!$instance){
                Write-Verbose "Making DNE Instance object for $InstanceID"
                $instance = [Amazon.EC2.Model.Reservation]::new()
                $instance.Instances = [Amazon.EC2.Model.Instance]::new()
                $($instance.Instances).InstanceId = $InstanceID
                $instance | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $InstanceID -Force
                $instance | Add-Member -MemberType NoteProperty -Name "Exists" -Value $false -Force
                $index = $dneinstances.Add($instance)
                # Making sure that we return a reference
                return $dneinstances[$index]
            } else {
                # If the object came from the master list then it will not have the ResourceID property
                if(!$instance.ResourceID){
                    Write-Verbose "Building filled out Instance object for $InstanceID"
                    # We will construct a new EC2 Instance object which make the properties writable
                    $inst = [Amazon.EC2.Model.Reservation]::new()
                    $inst."GroupNames" = $($instance | exp GroupNames)
                    $inst."Groups" = $($instance | exp Groups)
                    $inst."Instances" = [Amazon.EC2.Model.Instance]::new()
                    $inst."OwnerId" = $($instance | exp OwnerId)
                    $inst."RequesterId" = $($instance | exp RequesterId)
                    $inst."ReservationId" = $($instance | exp ReservationId)
                    $inst | Add-Member -MemberType NoteProperty -Name "Exists" -Value $true
                    $inst | Add-Member -MemberType NoteProperty -Name "ResourceID" -Value $InstanceID
                    $($inst | exp Instances)."InstanceId" = $InstanceID
                    # Adding the object to the filled out instances early so that calls to Get-Volume/Snapshot/AMI work properly
                    $filledOutInstances.Add($inst)
                    $($instance | exp Instances).PSObject.Properties | ForEach-Object {
                        # Once the code enters the switch statement, because of scopes, $_, will no longer be the property object so we will preserve it here
                        $property = $_
                        Switch ($property.Name) {
                            "BlockDeviceMappings" {
                                Write-Verbose "$InstanceID is calling Get-BlockDeviceMappings"
                                $blockDeviceMapObj = Get-BlockDeviceMappings -BlockDeviceMappings $property.Value -ResourceID $instanceId
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $blockDeviceMapObj -Force
                                break
                            }
                            "ImageId" {
                                Write-Verbose "$InstanceID is calling Get-AMI with $($instance | exp Instances | exp imageId)"
                                $ImageId = Get-AMI -Reference -ImageId $($instance | exp Instances | exp imageId)
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $ImageId -Force
                                break    
                            }
                            "IamInstanceProfile" {
                                $iam = $($instance | exp Instances | exp IamInstanceProfile)
                                if(!$iam){
                                    $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force    
                                } else {
                                    Write-Verbose "$InstanceID is filling out its IAM"
                                    $obj = [Amazon.EC2.Model.IamInstanceProfile]::new()
                                    Write-Verbose "$InstanceID is calling Get-IAM with $($iam | exp Id)"
                                    $iamObj = Get-IAM -IamId $($iam | exp Id) -IamArn $($iam | exp Arn) -Reference
                                    $obj | Add-Member -MemberType NoteProperty -Name "Id" -Value $iamObj -Force 
                                    $obj | Add-Member -MemberType NoteProperty -Name "Arn" -Value $iamObj -Force 
                                }
                                break  
                            }
                            "SecurityGroups" {
                                Write-Verbose "$InstanceID is filling out its security groups"
                                if(!$($instance | exp Instances | exp SecurityGroups)){
                                    $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
                                    break    
                                }
                                # Checking if it is a list
                                $isList = Assert-ObjectAList -Obj $($instance | exp Instances | exp SecurityGroups) 
                                if($isList){
                                    #$secGroupList = $($instance | exp Instances | exp SecurityGroups).Clone()
                                    #$secGroupList.Clear()
                                    $secGroupList = New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.GroupIdentifier]'
                                }
                                $obj = [Amazon.EC2.Model.GroupIdentifier]::new()
                                foreach($sg in $($instance | exp Instances | exp SecurityGroups)){
                                    $sgObj = Get-SecurityGroups -Reference -SecurityGroupId $($sg | exp GroupId) -SecurityGroupName $($sg | exp GroupName)
                                    $obj | Add-Member -MemberType NoteProperty -Name "GroupId" -Value $sgObj -Force 
                                    $obj | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $sgObj -Force
                                    if($isList){
                                        $secGroupList.Add($obj) | Out-Null
                                        $obj = [Amazon.EC2.Model.GroupIdentifier]::new()    
                                    }
                                }
                                if($isList){
                                    $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $secGroupList -Force
                                } else {
                                    $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $obj -Force    
                                }
                                break   
                            }
                            "KeyName" {
                                $keyName = [String]$($instance | exp Instances | exp KeyName).Trim()
                                Write-Verbose "$InstanceID is filling out its Key Name: $keyName"
                                $keys = Get-KeyPair -Reference -keyName $keyName -keyPairs $keyPairs
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $keys -Force  
                                break 
                            }
                            "LaunchTime" {
                                $launch = Get-Date $($instance.Instances.LaunchTime)
                                $($inst.Instances) | Add-Member -Force -MemberType NoteProperty -Name $property.Name -Value $launch   
                                break
                            }
                            "SubnetId" {
                                $subnet = Get-Subnet -Reference -subnetId $($instance | exp Instances | exp SubnetId) -Subnets $subnets
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $subnet -Force  
                                break  
                            }
                            "VpcId" {
                                Write-Verbose "$InstanceID is filling out its VPC: $($property.Value)"
                                $vpcId = $instance | exp Instances | exp VpcId
                                $vpc = Get-VPC -Reference -vpcId $vpcId
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $vpc -Force
                                break   
                            }
                            "NetworkInterfaces" {
                                Write-Verbose "$InstanceID is filling out its Network Interfaces"
                                # Checking if it is a list or not
                                if(!$($instance | exp Instances | exp NetworkInterfaces)){
                                    $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force  
                                    break  
                                }
                                $netAdaptList = New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.InstanceNetworkInterface]'
                                foreach($adapter in $($instance | exp Instances | exp NetworkInterfaces)){
                                    Write-Verbose "Building adapter"
                                    $adapt = [Amazon.EC2.Model.InstanceNetworkInterface]::new()
                                    # Just like above we need to copy the object to make all of the properties writeable
                                    foreach($property in $($adapter.PSObject.Properties)){

                                        # Security Groups
                                        if($property.Name -eq "Groups"){
                                            if(!$($property.Value)){
                                                $adapt | Add-Member -MemberType NoteProperty -Name "Groups" -Value $property.Value -Force
                                                continue    
                                            }
                                            Write-Verbose "Getting security groups for network interface"
                                            # Checking if it is a list
                                            $isList = Assert-ObjectAList -Obj $($adapter.Groups)
                                            if($isList){
                                                #$secGroupList = $($instance | exp Instances | exp SecurityGroups).Clone()
                                                #$secGroupList.Clear()
                                                $secGroupList = New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.GroupIdentifier]'
                                            }
                                            $obj = [Amazon.EC2.Model.GroupIdentifier]::new()
                                            foreach($sg in $adapter.Groups){
                                                $sgObj = Get-SecurityGroups -Reference -SecurityGroupId $($sg | exp GroupId) -SecurityGroupName $($sg | exp GroupName)
                                                $obj | Add-Member -MemberType NoteProperty -Name "GroupId" -Value $sgObj -Force 
                                                $obj | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $sgObj -Force
                                                if($isList){
                                                    $secGroupList.Add($obj) | Out-Null
                                                    $obj = [Amazon.EC2.Model.GroupIdentifier]::new()    
                                                }
                                            }
                                            if($isList){
                                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $secGroupList -Force
                                            } else {
                                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $obj -Force    
                                            }
                                        }

                                        # Subnet
                                        elseif($property.Name -eq "SubnetId"){
                                            Write-Verbose "Getting subnet for network interface"
                                            $subnetObj = Get-Subnet -Reference -subnetId $property.Value -Subnets $subnets
                                            $adapt | Add-Member -MemberType NoteProperty -Name "SubnetId" -Value $subnetObj -Force
                                        } 

                                        # VPC
                                        elseif($property.Name -eq "VpcId"){                                            
                                            if(!$($property.Value)){
                                                $adapt | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force    
                                            } else {
                                                Write-Verbose "Getting VPC for network interface"
                                                $vpcObj = Get-VPC -Reference -vpcId $property.Value
                                                $adapt | Add-Member -MemberType NoteProperty -Name $property.Name -Value $vpcObj -Force
                                            }
                                        } else {
                                            $adapt."$($property.Name)" = $property.Value
                                        } 

                                    }  
                                    $netAdaptList.Add($adapt) | Out-Null
                                }
                                $($inst.Instances) | Add-Member -MemberType NoteProperty -Name $property.Name -Value $netAdaptList -Force
                                Write-Verbose "$InstanceID is done filling out its Network Interfaces"
                                break  
                            }
                            "InstanceId" {
                                # Already added it above
                                break
                            }
                            default {
                                $($inst.Instances)."$($property.Name)" = $property.Value
                                break    
                            }
                        }
                    }
                    # Making sure that we return a reference
                    $filledOutInstances.Add($inst)
                    return $inst
                } else {
                    Write-Verbose "Returning filled out $InstanceID"
                    return $instance
                }
            }
        } else {
            $instance = $filledOutInstances | Where-Object { $_.ResourceID -eq $InstanceID }
            if(!$instance){
                Write-Verbose "No filled out Instance object has been made yet for $InstanceID"
                # Instead of copying code down here we can just call this function again
                $instance = Get-Instance -Reference -InstanceID $InstanceID
            } else {
                $instance = Get-Instance -Reference -InstanceID $InstanceID
            }
        }
        return $null

    }

    # DONE DONE DONE
    function Get-BlockDeviceMappings {
        param($BlockDeviceMappings,$ResourceID) 

        <#
         # How Amazon made their collections is a little weird. They either made their source code .net or c# but I am not sure
         # System.Collections.Generic.List`1[[Amazon.EC2.Model.InstanceBlockDeviceMapping, AWSSDK.EC2, Version=3.3.0.0, Culture=neutral, PublicKeyToken=885c28607f98e604]]
         # Instead of trying to recreate that, I can just check if this property is not Amazon.EC2.Model.InstanceBlockDeviceMapping, then copy it into a new variable and clear it
         # Amazon.EC2.Model.InstanceBlockDeviceMapping => single image attached to the instance
         # Amazon.EC2.Model.BlockDeviceMapping => ami block device mappings
         # Anything else assuming not null => multiple images are attached to the instance
         #>
        
        <#
         # I am leaving the above comment block for historical purposes. However, after refusing to believe that my hacky solution was correct I finally made a breakthrough
         # My weeks of digging lead me to following stack overflow post
         # https://stackoverflow.com/questions/2109412/generics-in-powershell-2-not-working
         # This will show you all the "Lists" that are associated with the [Amazon.EC2.Model.Instance] object
         # $([Amazon.EC2.Model.Instance]::new()).GetType() | exp DeclaredProperties |? { $_.PropertyType -like "*Collections*" } | Select Name, DeclaringType, PropertyType
         # Armed with these two pieces of information we can now reliably (and correctly?) make "proper" EC2 lists
         # New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.InstanceBlockDeviceMapping]'
         # It was that simple!
         #>


        if($BlockDeviceMappings){
            
            $blocksIsAList = $false
            # If it is neither of these properties than it is a list containing one of these properties
            $blocksIsAList = Assert-ObjectAList -Obj $BlockDeviceMappings
            if($blocksIsAList){
                $propertyType = $($BlockDeviceMappings[0]).GetType() | exp FullName
            } else {
                $propertyType = $($BlockDeviceMappings).GetType() | exp FullName    
            }
            
            # AMI Conditional
            if($propertyType -eq "Amazon.EC2.Model.BlockDeviceMapping"){
                Write-Verbose "$ResourceID is in BlockDeviceMapping conditional"
                if($blocksIsAList){
                    $blockList = New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.BlockDeviceMapping]'
                }
                foreach($blockObj in $BlockDeviceMappings){
                    $blocks = [Amazon.EC2.Model.BlockDeviceMapping]::new()
                    $ebsObj = [Amazon.EC2.Model.EbsBlockDevice]::new()
                    if($($blockObj | exp Ebs)){
                        foreach($property in $($($blockObj | exp Ebs).PSObject.Properties)){
                            if($property.Name -eq "SnapshotId"){
                                if($property.Value){
                                    $snapId = $($blockObj | exp Ebs | exp SnapshotId)
                                    Write-Verbose "$ResourceID in Get-BlockDeviceMapping is calling Get-Snapshot on $snapId"
                                    $snapObj = Get-Snapshot -Reference -SnapshotID $snapId 
                                    $ebsObj | Add-Member -MemberType NoteProperty -Name $property.Name -Value $snapObj -Force
                                } else {
                                    $ebsObj | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force    
                                }
                            } else {
                                $ebsObj | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force    
                            }
                        }
                    }
                    foreach($property in $($($blockObj).PSObject.Properties)){
                        if($property.Name -eq "Ebs"){
                            $blocks | Add-Member -MemberType NoteProperty -Name $property.Name -Value $ebsObj -Force
                        } else {
                            $blocks | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force 
                        }
                    }
                    if($blocksIsAList){
                        $blockList.Add($blocks)
                    }
                }
                if($blocksIsAList){
                    return $blockList
                } else {
                    return $blocks
                }
            }

            if($propertyType -eq "Amazon.EC2.Model.InstanceBlockDeviceMapping"){
                Write-Verbose "$ResourceID is in InstanceBlockDeviceMapping conditional"
                if($blocksIsAList){
                    $blocks = New-Object 'System.Collections.Generic.List[Amazon.EC2.Model.InstanceBlockDeviceMapping]'
                } 
            }
            foreach($block in $BlockDeviceMappings){
                $blockObj = [Amazon.EC2.Model.InstanceBlockDeviceMapping]::new() | Select-Object -Property * -ExcludeProperty "Ebs"
                if($($block | exp Ebs)){
                    <#
                     # I was having the issue where 
                     # $ebsObj | Add-Member -Force -MemberType NoteProperty -Name "VolumeId" -Value $volumeObj
                     # would not return any error but it would also not actually attach the object
                     # I feel that there is some sort of very low level (read: I am missing something obvious) powershell thing preventing it
                     # To get around this I figured out that when I create a new EBS object, I can exclude the VolumeID
                     # Then when I go to add it with the above command it will work 
                     #>
                    $ebsObj = [Amazon.EC2.Model.EbsInstanceBlockDevice]::new() | Select-Object -Property * -ExcludeProperty "VolumeId"
                    if($($block | exp Ebs | exp VolumeId)){
                        # The Ebs object has information in it 
                        $volumeId = $($block | exp Ebs | exp VolumeId)
                        Write-Verbose "$ResourceID in BlockDeviceMapping is calling Get-Volume for volumeId $volumeId"
                        $volumeObj = Get-Volume -Reference -VolumeID $volumeId
                    } else {
                        $volumeObj = $block | exp Ebs | exp VolumeId
                    }
                    if($($block | exp Ebs | exp AttachTime)){
                        $ebsObj.AttachTime = Get-Date $($block | exp Ebs | exp AttachTime)
                    } else {
                        $ebsObj.AttachTime = $block | exp Ebs | exp AttachTime  
                    }
                    $ebsObj.DeleteOnTermination = $block | exp Ebs | exp DeleteOnTermination
                    $ebsObj.Status = $block | exp Ebs | exp Status
                    $ebsObj | Add-Member -Force -MemberType NoteProperty -Name "VolumeId" -Value $volumeObj
                } else {
                    $ebsObj = $($block | exp Ebs)
                }

                $blockObj.DeviceName = $block | exp DeviceName
                $blockObj | Add-Member -Force -MemberType NoteProperty -Name "Ebs" -Value $ebsObj

                if($blocksIsAList){
                    $blocks.Add($blockObj) | Out-Null
                } else {
                    return $blockObj
                }
            }
            return $blocks
        } else {
            Write-Verbose "No Block Device Mappings object to fill out"
            return $BlockDeviceMappings
        }
    }

    # DONE DONE DONE
    function Convert-TextToObject {
        param(
            [String]$Text,
            [String]$Title,   
            [Regex]$Regex 
        )
        $descriptObj = New-Object PSObject
        $objects = Convert-IDSToObjects -Text $Text -Regex $Regex
        if($objects){
            $descriptObj | Add-Member -MemberType NoteProperty -Name $Title -Value $Text
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Instances" -Value $($objects | exp Instances)
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Images" -Value $($objects | exp Images)
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Volumes" -Value $($objects | exp Volumes)            
        } else { 
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Description" -Value $Text
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Instances" -Value $([System.Collections.ArrayList]@())
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Images" -Value $([System.Collections.ArrayList]@())
            $descriptObj | Add-Member -MemberType NoteProperty -Name "Volumes" -Value $([System.Collections.ArrayList]@())            
        }
        return $descriptObj   
    }

    # DONE DONE DONE
    function Convert-IDSToObjects {
        param(
            [String]$Text,
            [Regex]$Regex
        )
        Write-Verbose "Checking if, $Text, has any IDs that we can pull information out of"
        $obj = New-Object PSObject
        $idMatches = $Regex.Matches($Text)
        if($idMatches.Success){
            # Currently we are only going to support AMI, Instance, and Volume
            $amiObjs = [System.Collections.ArrayList]@()
            $instObjs = [System.Collections.ArrayList]@()
            $volObjs = [System.Collections.ArrayList]@()
            foreach($match in $idMatches){
                Write-Verbose "Working with this match"
                Write-Verbose "$($match.Value)"
                Switch -Regex ($match.Value) {
                    "^i-*" {
                        Write-Verbose "Instance Match"
                        $inst = Get-Instance -Reference -InstanceID $_
                        $instObjs.Add($inst) | Out-Null
                        break    
                    }
                    "^ami-*" {
                        Write-Verbose "AMI Match"
                        $image = Get-AMI -Reference -imageId $_
                        $amiObjs.Add($image) | Out-Null
                        break   
                    }
                    "^vol-*" {
                        Write-Verbose "Volume Match"
                        $volume = Get-Volume -Reference -VolumeID $_ 
                        $volObjs.Add($volume) | Out-Null
                        break
                    }
                    default {
                        # We can come back after everything has been gathered and use this list of unknowns to add more functionality to this
                        $unknownIds.Add($_) | Out-Null
                        break
                    }
                }
            }
            $obj | Add-Member -MemberType NoteProperty -Name "Instances" -Value $instObjs
            $obj | Add-Member -MemberType NoteProperty -Name "Images" -Value $amiObjs
            $obj | Add-Member -MemberType NoteProperty -Name "Volumes" -Value $volObjs
        } else {
            $obj = $null
        }
        return $obj
    }
    
    # DONE DONE DONE 
    function Confirm-Resource {
        param($FilledOutList, $MasterList, $DNEList, $ResourceID)
        # When we build the object initially we put its ResourceID as a property.
        $obj = $FilledOutList | Where-Object { $($_.ResourceID) -and ($($_ | exp ResourceID) -eq $ResourceID) }
        if(!$obj){
            Write-Verbose "No filled out object found for $ResourceID"
            # However for the master list we will not be that lucky
            if($ResourceID -match "^i-.*"){
                # Instance objects are nested
                $obj = $MasterList | Where-Object { $($_ | exp Instances | exp InstanceId) -eq $ResourceID }
            } else {
                foreach($resource in $MasterList){
                    foreach($property in $resource.PSObject.Properties){
                        if($property.TypeNameOfValue -eq "System.String" -and $property.Value -eq $ResourceID){
                            $obj = $resource
                            break
                        }    
                    }
                    if($obj){
                        break
                    } 
                }
            }
            # If it is not in either the filled out or master lists then the last place we check is the does not exist list
            # Since we got to construct this object that means we can do what we did above for the filled out list check
            if(!$obj){
                Write-Verbose "No object found for $ResourceID"
                $obj = $DNEList | Where-Object { $($_.ResourceID) -and ($($_ | exp ResourceID) -eq $ResourceID) }
                if(!$obj){
                    Write-Verbose "$ResourceID not found in DNE List"
                    $obj = $false
                } else {
                    Write-Verbose "$ResourceID found on DNE List"
                }
            } else {
                Write-Verbose "Object found for $ResourceID"
            }
        } else {
            Write-Verbose "Filled out object found for $ResourceID"
        }
        return $obj
    }

    function Assert-ObjectAList {
        param($Obj)
        if($Obj){
            $type = $obj.GetType() | exp FullName
            if($type -like "*System.Collections.Generic.List*"){
                return $true
            } else {
                return $false
            }
        } else {
            return $null
        }
    } 


    <# /INNER FUNCTIONS #>

    Write-Verbose "Formatting EC2 information"


    <# DHCP #>
    if($NoProgress -or $v){
        Write-Verbose ""
        Write-Verbose "Starting DHCP"
    }
    Sleep 2
    foreach($dhcpOpt in $DHCP) {
        $dhcpId = $dhcpOpt | exp DhcpOptionsId
        #Write-Verbose "Working with $dhcpId"
        $obj = Get-DHCP -dhcpId $dhcpId
        #Write-Verbose "Finished with $dhcpId"
    }
    <#/ DHCP #>

    <# VPC #>
    Write-Verbose ""
    Write-Verbose "Starting VPC"
    Sleep 2
    foreach($vpcObj in $VPC) {
        $vpcId = $vpcObj | exp VpcId
        #Write-Verbose "Working with $vpcId"
        $obj = Get-VPC -vpcId $vpcId
        #Write-Verbose "Finished with $vpcId"
    }
    <#/ VPC #>

    <# EC2 INSTANCES #>
    Write-Verbose ""
    Write-Verbose "Starting instances"
    Sleep 2
    #$tester = Get-ec2instance "i-099c8408b362de779"
    foreach($instance in $instances[0..1]) {#$tester){# 
        $instId = $instance | exp Instances | exp InstanceId
        #Write-Verbose "Working with instance $instId"
        Write-Verbose "Starting instance $instId"
        Write-Verbose ""
        $obj = Get-Instance -InstanceID $instId
        #Write-Verbose "Finished with $instId"
    }
    <#/ EC2 INSTANCES #>

    <# EC2 SNAPSHOTS #>
    Write-Verbose ""
    Write-Verbose "Starting snapshots"
    Sleep 2
    foreach($snapshot in $snapshots[0..3]){
        $snapId = $snapshot | exp SnapshotId
        Write-Verbose "Working with snapshot $snapId"
        $obj = Get-Snapshot -SnapshotID $snapId
        Write-Verbose "Finished with $snapId"
    }
    <#/ EC2 SNAPSHOTS #>

    <# EC2 VOLUMES #>
    Write-Verbose ""
    Write-Verbose "Starting volumes"
    Sleep 2
    foreach($volume in $volumes[0..3]){# $(Get-Random -Count 5 $volumes)){
        $volId = $volume | exp VolumeId
        Write-Verbose "Working with volume $volId"
        $obj = Get-Volume -VolumeId $volId
        Write-Verbose "Finished with volume $volId"
    }
    <#/ EC2 VOLUMES #>

    <# EC2 AMI #>
    Write-Verbose ""
    Write-Verbose "Starting AMI"
    Sleep 2
    foreach($ami in $AMIs[0..3]){
        $amiId = $ami | exp imageId
        Write-Verbose "Working with volume $amiId"
        $obj = Get-AMI -imageId $amiId
        Write-Verbose "Finished with volume $amiId"
    }
    <#/ EC2 AMI #>

    <# EC2 SECURITY GROUPS #>
    Write-Verbose ""
    Write-Verbose "Starting Security Groups"
    Sleep 2
    foreach($sg in $SecurityGroups[0..3]){
        $sgId = $sg | exp GroupId
        $sgName = $sg | exp GroupName
        Write-Verbose "Working with SG $sgId"
        $obj = Get-SecurityGroups -SecurityGroupId $sgId -SecurityGroupName $sgName
        Write-Verbose "Finished with SG $sgId"
    }
    <#/ EC2 SECURITY GROUPS #>

    <# MASTER OBJECT #>
    <#
    $masterObj = [pscustomobject][ordered]@{
        "Instances"      = $filledOutInstances
        "Snapshots"      = $filledOutSnapshots
        "Volumes"        = $filledOutVolumes
        "AMI"            = $filledOutAMIs 
        "SecurityGroups" = $filledOutSecGroups
        "IAM"            = $filledOutIam
        "VPC"            = $filledOutVpc
        "DHCPOptions"    = $filledOutDhcp
        "Subnets"        = $filledOutSubnets
        "KeyPairs"       = $filledOutKeyPairs
        "DNEResources"   = $masterDNE
        "UnknownIDs"     = $unknownIds
    }#>
    # Credit: https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
    #$masterObj.PSObject.TypeNames.Insert(0,'AWS.EC2.MAP')
    #$defaultDisplaySet = "Instances","Snapshots","Volumes","AMI","SecurityGroups","IAM","VPC","DHCPOptions","Subnets","KeyPairs"
    #$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultDisplaySet)
    #$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    #$masterObj | Add-Member MemberSet PSStandardMembers $PSStandardMembers 
    <# /MASTER OBJECT #>

    #$($masterObj | exp instances)[0] | exp instances | all | out-file "output"

    return $masterObj
}


<# GLOBALS #>
#$Global:ErrorActionPreference = 'Stop'
$masterObj = Get-AWSEC2 -v
$masterObj | Select * | Format-List
$masterobj | exp Instances |% { $_ | exp instances | Select * | Format-List; break}
<# /GLOBALS #>
