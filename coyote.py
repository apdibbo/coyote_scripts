#!/usr/bin/python
import json
import sys
import os
import paramiko
from time import gmtime, strftime
from subprocess import Popen, PIPE
from ConfigParser import SafeConfigParser

env = os.environ.copy()

with open('coyote_config.json') as config_file: 
    config = json.load(config_file)

softcorebuffer              = config['softcorebuffer']
hardcorebuffer              = config['hardcorebuffer']
staticpartition             = config['staticpartition']
largeHypervisorCores        = config['largeHypervisorCores']
emptyHVBuffer               = config['emptyHVBuffer']
staticFlavor                = config['staticFlavor']
opportunisticFlavor         = config['opportunisticFlavor']
vwnStaticNamePrefix         = config['vwnStaticNamePrefix']
vwnOpportunisticNamePrefix  = config['vwnOpportunisticNamePrefix']
vwnImageName                = config['vwnImageName']
networkName                 = config['networkName']
availabilityZone            = config['availabilityZone']
configDrive                 = config['configDrive']
userDataPath                = config['userDataPath']
coyoteKeyPair               = config['coyoteKeyPair']
coyotePrivateKeyPath        = config['coyotePrivateKeyPath']
coyoteRemoteUser            = config['coyoteRemoteUser']
jsonTrackingFile            = config['jsonTrackingFile']
metadata                    = config['metadata']
coyoteRCPath                = config['coyoteRCPath']
sourcecmd                   = config['sourcecmd']

def disable_host(host):
    print(host)
    ssh = paramiko.SSHClient()
    pkey = paramiko.RSAKey.from_private_key_file(coyotePrivateKeyPath)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=coyoteRemoteUser, pkey=pkey)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("/usr/local/bin/condor_disable.sh")

def cl(c):
        p = Popen(sourcecmd+c, shell=True, stdout=PIPE, env=env)
        return p.communicate()[0]

nodelist = json.loads(cl("openstack server list --long -f json"))

flavorListPre = json.loads(cl("openstack flavor list --long -f json"))
flavorList = {}
for flavor in flavorListPre:
     flavorList[flavor["Name"]] = flavor


instanceCreateString = "openstack server create --key-name "+ coyoteKeyPair + " --image " + vwnImageName + " --user-data " + userDataPath + " --network " + networkName + " --config-drive " + str(configDrive) + " --availability-zone " + availabilityZone
propertyString = ""
for metadataitem in metadata.keys():
    propertyString += " --property '" + metadataitem + "'='" + metadata[metadataitem] + "'"

try:
    with open(jsonTrackingFile) as jsonfile:
        vwnJSON = json.load(jsonfile)
except IOError as e :
    vwnJSON = {}

vwnToCleanUp = []

for vwn in vwnJSON:
    present = False
    for node in nodelist:
        if vwn == node["Name"]:
            present = True
            break
    if present == False:
        vwnToCleanUp.append(vwn)

for vwn in vwnToCleanUp:
    del vwnJSON[vwn]


### Check for virtual worker nodes which are down or errored and remove
for node in nodelist:
    if "vwn" in node["Name"]:
        ipAddr = ""
        try:
            ipAddr = node["Networks"].split("=")[1]
        except IndexError:
            print("Node has no IP")
        try:
            vwnJSON[node["Name"]]["Status"] = node["Status"]
            vwnJSON[node["Name"]]["IP Address"] = ipAddr
            if node["Status"] == "ERROR" or node["Power State"] == "Shutdown":
                print node["Name"] + " - " + node["Power State"] + " - is virtual worker"
                print "Deleting Instance: " + node["ID"]
                cl( "openstack server delete " + node["ID"])
                del vwnJSON[node["Name"]]
        except:
            print("node problem")


disabledCores = 0
disabledStaticInstances = 0
disableableOppInstance = ""
disableableStaticInstance = ""
for node in vwnJSON:
    if vwnJSON[node]["Disabled"] == True:
        disabledCores += vwnJSON[node]["VCPUs"]
        if vwnJSON[node]["Type"] == "Static":
            disabledStaticInstances += 1
    else:
        if vwnJSON[node]["Type"] == "Static":
            disableableStaticInstance = node
        elif vwnJSON[node]["Type"] == "Opportunistic":
            disableableOppInstance = node

print("Disabled Cores = " + str(disabledCores))
print("Disabled Static Instances = " + str(disabledStaticInstances))
print("Disableable Static Instance - " + disableableStaticInstance)
print("Disableable Opportunistic Instance - " + disableableOppInstance)




limits = json.loads(cl("openstack limits show --absolute -f json"))
for limit in limits:
 if limit["Name"] == "totalCoresUsed":
        usedcores = limit["Value"]

print "Condor Used Cores: " + str(usedcores)

novacomputeservices = json.loads(cl("openstack compute service list -f json"))

hypervisors = json.loads(cl("openstack hypervisor list --long -f json"))
emptyLargeHypervisors = 0
totalUsedCores = 0
totalCores = 0
for hypervisor in hypervisors:
    if hypervisor["State"] == "up":
        for novaservice in novacomputeservices:
            if novaservice["Host"] == hypervisor["Hypervisor Hostname"] and novaservice["Status"] == "enabled":
                totalCores += hypervisor["vCPUs"]
                if hypervisor["vCPUs"] >= largeHypervisorCores and hypervisor["vCPUs Used"] == 0:
                    emptyLargeHypervisors += 1
        totalUsedCores += hypervisor["vCPUs Used"]

availablecores = totalCores - totalUsedCores

availableEmptyLargeHypervisors = emptyLargeHypervisors - emptyHVBuffer


print "Available cores: " + str(availablecores)
print "Avalilable Empty Large Hypervisors - " + str(availableEmptyLargeHypervisors)

availablecondorcores = availablecores - softcorebuffer

print str(availablecondorcores) + " - available to condor"

nowtime = strftime("%Y-%m-%d-%H-%M-%S", gmtime())

nameString = ""

if 0 > availableEmptyLargeHypervisors and disabledStaticInstances < (0 - availableEmptyLargeHypervisors):
    print("Available Empty Large Hypervisors < 0")
    print("Draining " + disableableStaticInstance + " - " + vwnJSON[disableableStaticInstance]["IP Address"])
    vwnJSON[disableableStaticInstance]["Disabled"] = True
    #disable_host(vwnJSON[disableableStaticInstance]["IP Address"])

if 0 > availablecondorcores and disabledCores < (0 - availablecondorcores):
    print("Available Empty Large Hypervisors < 0")
    try: 
        print("Draining " + disableableOppInstance + " - " + vwnJSON[disableableOppInstance]["IP Address"])
        vwnJSON[disableableOppInstance]["Disabled"] = True
        #disable_host(vwnJSON[disableableOppInstance]["IP Address"])
    except KeyError: 
        print("Disabled Oppertunistic Instance has no value")


if 0 < availableEmptyLargeHypervisors:
    flavorString = " --flavor " + staticFlavor
    flavorName = staticFlavor
    nameString = vwnStaticNamePrefix
    nameString += "-" + nowtime
    vwnType = "Static"

if nameString != "":
    print "Creating new virtual workernode - " + nameString
    #print(instanceCreateString + propertyString + flavorString + " " + nameString)

    if nameString not in vwnJSON:
        vwnJSON[nameString] = { "Status":"Active", "Disabled":False,"FlavorID":flavorList[flavorName]["ID"],"Flavor":flavorName,"VCPUs":flavorList[flavorName]["VCPUs"], "Type":vwnType }

with open(jsonTrackingFile, 'w') as jsonfile:
    json.dump(vwnJSON, jsonfile)
