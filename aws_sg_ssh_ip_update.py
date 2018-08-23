#!/usr/bin/python

# =============================================================================
# =============================================================================
# Created by: D.A.J.Simpson on: 27 July 2018
# =============================================================================
# =============================================================================

# Packages used
import datetime, requests, boto3

# =============================================================================
# F U N C T I O N: updateSecurityGroup
#
# This function does most of the work. It looks up the details for the
# security group to be checked. If the SSH rule on port 22 is not using
# the provided IP adress (NEW_IP parameter) then the out-of-date rule
# will be revoked and a new rule added.
#
# Parameters: SG_ID  - The Security Group ID, e.g. sg-12345678901234567
#             NEW_IP - The IP address that is required for the SSH rule
#
# =============================================================================
def updateSecurityGroup(SG_ID,NEW_IP,PORT):

   # Get the Security Group information
   ec2 = boto3.resource('ec2')
   try:
      sg = ec2.SecurityGroup(SG_ID)
      for ipp in sg.ip_permissions:
         if PORT == ipp['FromPort']:
            ipR = ipp['IpRanges']
   except:
      print("ERROR: Problem getting information about Security Group with ID: "+SG_ID)
      return

   # Check that an existing rule was found
   try:
      ipR
   except NameError:
      SG_IP="0.0.0.0/0"
      Do_Revoke=0
   else:
      # Get the IP that is defined in the current SSH rule
      SG_IP=ipR[0]['CidrIp']
      Do_Revoke=1

   # Define a string to be used as the rule's description, if an update is required
   DT_INFO="Updated "+datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

   # If the IPs are not the same then some updates are required
   if NEW_IP != SG_IP :
      if 1 == Do_Revoke :
         # Revoke the old port rule
         try:
            sg.revoke_ingress( DryRun=False, IpPermissions=[{'FromPort':PORT,'IpProtocol':'tcp','IpRanges':[{'CidrIp':SG_IP},],'Ipv6Ranges':[],'PrefixListIds':[],'ToPort':PORT,'UserIdGroupPairs':[]}] )
         except:
            print("ERROR: Removal of the incorrect rule has failed for Security Group: "+SG_ID)
            print("Please login to the AWS Management Console and check")
            return
            
      try:
      	sg.authorize_ingress( DryRun=False, IpPermissions=[{'FromPort':PORT,'IpProtocol':'tcp','IpRanges':[{'CidrIp':NEW_IP,'Description':DT_INFO},],'Ipv6Ranges':[],'PrefixListIds':[],'ToPort':PORT,'UserIdGroupPairs':[]}] )
      except:
         print("ERROR: Adding the new rule has failed for Security Group: "+SG_ID)
         print("Please login to the AWS Management Console and check")
         return

      print("Update made to the Security Group ("+SG_ID+") to enable port PORT access from IP: "+NEW_IP)
   else:
      print("No updates were required to Security Group: "+SG_ID)

#
# F U N C T I O N: updateSecurityGroup - END
# =============================================================================
# =============================================================================


# =============================================================================
#                            M A I N  P R O G R A M
# =============================================================================

# Definitions
IP_SOURCE_ADDR='https://v4.ifconfig.co/ip'

# Get the 'local' IP address
ip_request = requests.get(IP_SOURCE_ADDR)
My_IP = ip_request.text
# Add the CIDR subnet suffix to the IP
My_IP=''.join([My_IP.rstrip(),"/32"])


updateSecurityGroup('sg-38058e50',My_IP,22)
updateSecurityGroup('sg-38058e50',My_IP,80)
updateSecurityGroup('sg-38058e50',My_IP,443)
updateSecurityGroup('sg-0a9d3cd5337b69a45',My_IP,22)
updateSecurityGroup('sg-0a9d3cd5337b69a45',My_IP,80)
updateSecurityGroup('sg-0a9d3cd5337b69a45',My_IP,443)

#                                  Done
# =============================================================================
