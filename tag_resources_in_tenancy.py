# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

##########################################################################
# tag_compute_in_tenancy.py
#
# @author: Adi Zohar
#
# Supports Python  3
##########################################################################
# Info:
#    List all compute tags in Tenancy
#
# Connectivity:
#    Option 1 - User Authentication
#       $HOME/.oci/config, please follow - https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm
#       OCI user part of tagComputeGroup group with below Policy rules:
#          Allow group tagComputeGroup to inspect compartments in tenancy
#          Allow group tagComputeGroup to inspect tenancies in tenancy
#          Allow group tagComputeGroup to use instances in tenancy
#          Allow group tagComputeGroup to use tag-namepsace in tenancy
#
#    Option 2 - Instance Principle
#       Compute instance part of DyntagComputeGroup dynamic group with policy rules:
#          Allow dynamic group DyntagComputeGroup to inspect compartments in tenancy
#          Allow dynamic group DyntagComputeGroup to inspect tenancies in tenancy
#          Allow dynamic group DyntagComputeGroup to use instances in tenancy
#          Allow dynamic group DyntagComputeGroup to use tag-namespace in tenancy
#
##########################################################################
# Modules Included:
# - oci.identity.IdentityClient
#
# APIs Used:
# - IdentityClient.list_compartments         - Policy COMPARTMENT_INSPECT
# - IdentityClient.get_tenancy               - Policy TENANCY_INSPECT
# - IdentityClient.list_region_subscriptions - Policy TENANCY_INSPECT
# - ComputeClient.list_instances             - Policy
#
##########################################################################
# Application Command line parameters
#
#   -t config       - Config file section to use (tenancy profile)
#   -p proxy        - Set Proxy (i.e. www-proxy-server.com:80)
#   -ip             - Use Instance Principals for Authentication
#   -dt             - Use Instance Principals with delegation token for cloud shell
#   -cp compartment - filter by compartment name or id
#   -rg region      - filter by region name
#   -deftag tag     - definetags
#   -freetag tag    - freeform tag
#   -deltag         - specify if to delete the tag
##########################################################################

from __future__ import print_function
import sys
import argparse
import datetime
import oci
import json
import os

# global variables
assign_tag_namespace = ""
assign_tag_key = ""
assign_tag_value = ""
warnings = 0
data = []
cmd = ""


##########################################################################
# Print banner
##########################################################################
def print_banner(cmd, tenancy):
    print_header("Running Tag Conpute")
    print("Written By Adi Zohar, Nov 2020")
    print("Starts at " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("Command Line  : " + ' '.join(x for x in sys.argv[1:]))
    if cmd.deftag:
        print("Tag Namespace : " + assign_tag_namespace)
    print("Tag Key       : " + assign_tag_key)
    print("Tag Value     : " + assign_tag_value)
    print("Tenant Name   : " + str(tenancy.name))
    print("Tenant Id     : " + tenancy.id)
    print("")


##########################################################################
# Print header centered
##########################################################################
def print_header(name):
    chars = int(90)
    print("")
    print('#' * chars)
    print("#" + name.center(chars - 2, " ") + "#")
    print('#' * chars)


##########################################################################
# Handle Tag
##########################################################################
def command_line():
    global cmd
    global assign_tag_namespace
    global assign_tag_key
    global assign_tag_value

    try:
        # Get Command Line Parser
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', default="", dest='config_profile', help='Config file section to use (tenancy profile)')
        parser.add_argument('-p', default="", dest='proxy', help='Set Proxy (i.e. www-proxy-server.com:80) ')
        parser.add_argument('-cp', default="", dest='compartment', help='Filter by Compartment Name or Id')
        parser.add_argument('-rg', default="", dest='region', help='Filter by Region Name')
        parser.add_argument('-deftag', default="", dest='deftag', help='Defined Tag to Assign in format - namespace.key=value')
        parser.add_argument('-freetag', default="", dest='freetag', help='Freeform Tag to Assign in format - key=value')
        parser.add_argument('-deltag', action='store_true', default=False, dest='deltag', help='Mark if to delete the tag')
        parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
        parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')
        parser.add_argument('-print', action='store_true', default=False, dest='print_report', help='Print full Report')
        cmd = parser.parse_args()

        # Check if any tag specified
        if not (cmd.deftag or cmd.freetag):
            parser.print_help()
            print("\nYou must specify tag to assign !!")
            raise SystemExit

        # Check if any tag specified
        if cmd.deftag and cmd.freetag:
            parser.print_help()
            print("\nYou must specify only one type of tag to assign !!")
            raise SystemExit

        # if defined tag
        if cmd.deftag:
            assign_tag_namespace = cmd.deftag.split(".")[0]
            assign_tag_key = cmd.deftag.split(".")[1].split("=")[0]
            assign_tag_value = cmd.deftag.split(".")[1].split("=")[1]
            if not (assign_tag_namespace or assign_tag_key or assign_tag_value):
                print("Error with tag format, must be in format - namespace.key=value")
                raise SystemExit

        # if freeform tag
        if cmd.freetag:
            assign_tag_key = cmd.freetag.split("=")[0]
            assign_tag_value = cmd.freetag.split("=")[1]
            if not (assign_tag_key or assign_tag_value):
                print("Error with tag format, must be in format - key=value")
                raise SystemExit

        # return the command line
        return cmd

    except Exception as e:
        raise RuntimeError("Error in command_line: " + str(e.args))


##########################################################################
# check service error to warn instead of error
##########################################################################
def check_service_error(code):
    return ('max retries exceeded' in str(code).lower() or
            'auth' in str(code).lower() or
            'notfound' in str(code).lower() or
            code == 'Forbidden' or
            code == 'TooManyRequests' or
            code == 'IncorrectState' or
            code == 'LimitExceeded'
            )


##########################################################################
# Create signer for Authentication
# Input - config_profile and is_instance_principals and is_delegation_token
# Output - config and signer objects
##########################################################################
def create_signer(config_profile, is_instance_principals, is_delegation_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print_header("Error obtaining instance principals certificate, aborting")
            raise SystemExit

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                raise SystemExit

            # check if file exist
            if not os.path.isfile(env_config_file):
                print("*** Config File " + env_config_file + " does not exist, Abort. ***")
                print("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            raise SystemExit

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        config = oci.config.from_file(
            oci.config.DEFAULT_LOCATION,
            (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
        )
        signer = oci.signer.Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
            private_key_content=config.get("key_content")
        )
        return config, signer


##########################################################################
# Check if tag namespace exist
##########################################################################
def read_tag_namespaces(identity, tenancy):
    try:
        print("\nReading Tag Namespaces...")
        tagnamespaces = oci.pagination.list_call_get_all_results(
            identity.list_tag_namespaces,
            tenancy.id,
            include_subcompartments=True,
            lifecycle_state='ACTIVE'
        ).data

        ###########################
        # check if namespace exit
        ###########################
        assign_tag_namespace_obj = None
        for tagnamespace in tagnamespaces:
            if tagnamespace.name == assign_tag_namespace:
                assign_tag_namespace_obj = tagnamespace
                print("   Found Tag Namespace '" + assign_tag_namespace + "', id = " + tagnamespace.id)
                break

        if not assign_tag_namespace_obj:
            print("Could not find tag namespace " + assign_tag_namespace)
            print("Abort.")
            raise SystemExit

        # check tag key
        tags = oci.pagination.list_call_get_all_results(
            identity.list_tags,
            assign_tag_namespace_obj.id,
            lifecycle_state='ACTIVE'
        ).data

        tag_key_found = False
        for tag in tags:
            if tag.name == assign_tag_key:
                tag_key_found = True
                print("   Found Tag Key '" + assign_tag_key + "', id = " + tag.id)
                break

        if not tag_key_found:
            print("Could not find tag Key " + assign_tag_key)
            print("Abort.")
            raise SystemExit

    except Exception as e:
        raise RuntimeError("\nError checking tagnamespace - " + str(e))


##########################################################################
# Load compartments
##########################################################################
def identity_read_compartments(identity, tenancy):

    print("Loading Compartments...")
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity.list_compartments,
            tenancy.id,
            compartment_id_in_subtree=True,
        ).data

        # Add root compartment which is not part of the list_compartments
        compartments.append(tenancy)

        # compile new compartment object
        filtered_compartment = []
        for compartment in compartments:
            # skip non active compartments
            if compartment.id != tenancy.id and compartment.lifecycle_state != oci.identity.models.Compartment.LIFECYCLE_STATE_ACTIVE:
                continue

            # if filter by compartment name or id if specified
            if cmd.compartment:
                if compartment.id != cmd.compartment and compartment.name != cmd.compartment:
                    continue

            filtered_compartment.append(compartment)

        print("    Total " + str(len(filtered_compartment)) + " compartments loaded.")
        return filtered_compartment

    except Exception as e:
        raise RuntimeError("Error in identity_read_compartments: " + str(e.args))


##########################################################################
# Handle Instances
##########################################################################
def handle_instances(client, compartment, region_name):

    global data
    global warnings

    try:
        cnt = 0
        cnt_added = 0
        cnt_deleted = 0

        ############################################
        # Retrieve instances
        ############################################
        array = []
        try:
            array = oci.pagination.list_call_get_all_results(
                client.list_instances,
                compartment.id,
                sort_by="DISPLAYNAME"
            ).data

        except oci.exceptions.ServiceError as e:
            if check_service_error(e.code):
                warnings += 1
                print("        Instances...Warnings ")
                return
            raise

        # loop on Array
        for arr in array:
            if arr.lifecycle_state == "TERMINATING" or arr.lifecycle_state == "TERMINATED":
                continue

            defined_tags, freeform_tags, tags_process = handle_tags(arr.defined_tags, arr.freeform_tags)

            # if tag modified:
            if tags_process:
                client.update_instance(
                    arr.id,
                    oci.core.models.UpdateInstanceDetails(
                        freeform_tags=freeform_tags,
                        defined_tags=defined_tags
                    )
                )

            ############################################
            # Add data to array
            ############################################
            value = ({
                'region_name': region_name,
                'compartment_name': str(compartment.name),
                'type': 'instance',
                'name': str(arr.display_name),
                'defined_tags': defined_tags,
                'freeform_tags': freeform_tags,
                'tags_process': tags_process
            })

            data.append(value)
            cnt += 1

            if tags_process == "Added":
                cnt_added += 1
            if tags_process == "Deleted":
                cnt_deleted += 1

        # print instances for the compartment
        if cnt == 0:
            print("        Instances (-)")
        else:
            if cmd.deltag:
                print("        Instances     - " + str(cnt) + ", Tag Deleted = " + str(cnt_deleted))
            else:
                print("        Instances     - " + str(cnt) + ", Tag Added = " + str(cnt_added))

    except Exception as e:
        raise RuntimeError("Error in handle_instances: " + str(e.args))


##########################################################################
# Handle Instances
##########################################################################
def handle_block_volumes(client, compartment, region_name):

    global data
    global warnings

    try:
        cnt = 0
        cnt_added = 0
        cnt_deleted = 0

        array = []
        try:
            array = oci.pagination.list_call_get_all_results(
                client.list_volumes,
                compartment.id,
                sort_by="DISPLAYNAME"
            ).data

        except oci.exceptions.ServiceError as e:
            if check_service_error(e.code):
                warnings += 1
                print("        Block Volumes...Warnings ")
                return
            raise

        # loop on Array
        for arr in array:
            if arr.lifecycle_state == "TERMINATING" or arr.lifecycle_state == "TERMINATED":
                continue

            defined_tags, freeform_tags, tags_process = handle_tags(arr.defined_tags, arr.freeform_tags)

            # if tag modified:
            if tags_process:
                client.update_volume(
                    arr.id,
                    oci.core.models.UpdateVolumeDetails(
                        freeform_tags=freeform_tags,
                        defined_tags=defined_tags
                    )
                )

            ############################################
            # Add data to array
            ############################################
            value = ({
                'region_name': region_name,
                'compartment_name': str(compartment.name),
                'type': 'volume',
                'name': str(arr.display_name),
                'defined_tags': defined_tags,
                'freeform_tags': freeform_tags,
                'tags_process': tags_process
            })

            data.append(value)
            cnt += 1

            if tags_process == "Added":
                cnt_added += 1
            if tags_process == "Deleted":
                cnt_deleted += 1

        # print instances for the compartment
        if cnt == 0:
            print("        Block Volumes (-)")
        else:
            if cmd.deltag:
                print("        Block Volumes - " + str(cnt) + ", Tag Deleted = " + str(cnt_deleted))
            else:
                print("        Block Volumes - " + str(cnt) + ", Tag Added = " + str(cnt_added))

    except Exception as e:
        raise RuntimeError("Error in handle_block_volumes: " + str(e.args))


##########################################################################
# Handle Instances
##########################################################################
def handle_boot_volumes(identity, tenancy_id, client, compartment, region_name):

    global data
    global warnings

    try:
        cnt = 0
        cnt_added = 0
        cnt_deleted = 0

        array = []
        availability_domains = identity.list_availability_domains(tenancy_id).data
        for ad in availability_domains:
            try:
                array = oci.pagination.list_call_get_all_results(
                    client.list_boot_volumes,
                    ad.name,
                    compartment.id
                ).data

            except oci.exceptions.ServiceError as e:
                if check_service_error(e.code):
                    warnings += 1
                    print("        Boot Volumes...Warnings ")
                    return
                raise

            # loop on Array
            for arr in array:
                if arr.lifecycle_state == "TERMINATING" or arr.lifecycle_state == "TERMINATED":
                    continue

                defined_tags, freeform_tags, tags_process = handle_tags(arr.defined_tags, arr.freeform_tags)

                # if tag modified:
                if tags_process:
                    client.update_boot_volume(
                        arr.id,
                        oci.core.models.UpdateBootVolumeDetails(
                            freeform_tags=freeform_tags,
                            defined_tags=defined_tags
                        )
                    )

                ############################################
                # Add data to array
                ############################################
                value = ({
                    'region_name': region_name,
                    'compartment_name': str(compartment.name),
                    'type': 'boot volume',
                    'name': str(arr.display_name),
                    'defined_tags': defined_tags,
                    'freeform_tags': freeform_tags,
                    'tags_process': tags_process
                })

                data.append(value)
                cnt += 1

                if tags_process == "Added":
                    cnt_added += 1
                if tags_process == "Deleted":
                    cnt_deleted += 1

        # print instances for the compartment
        if cnt == 0:
            print("        Boot Volumes (-)")
        else:
            if cmd.deltag:
                print("        Boot Volumes  - " + str(cnt) + ", Tag Deleted = " + str(cnt_deleted))
            else:
                print("        Boot Volumes  - " + str(cnt) + ", Tag Added = " + str(cnt_added))

    except Exception as e:
        raise RuntimeError("Error in handle_boot_volumes: " + str(e.args))


##########################################################################
# Handle Tag
##########################################################################
def handle_tags(defined_tags, freeform_tags):
    try:
        tags_process = ""

        ############################################
        # handle defined tags
        ############################################
        if cmd.deftag:
            defined_tags_exist = False
            if assign_tag_namespace in defined_tags:
                if assign_tag_key in defined_tags[assign_tag_namespace]:
                    if defined_tags[assign_tag_namespace][assign_tag_key] == assign_tag_value:
                        defined_tags_exist = True

            # Del Key
            if cmd.deltag:
                if defined_tags_exist:
                    defined_tags.pop(assign_tag_namespace, None)
                    tags_process = "Deleted"

            # Add Key
            else:
                if not defined_tags_exist:
                    defined_tags[assign_tag_namespace] = {assign_tag_key: assign_tag_value}
                    tags_process = "Added"

        ############################################
        # handle freeform tags
        ############################################
        if cmd.freetag:
            freeform_tags_exist = False
            if assign_tag_key in freeform_tags:
                if freeform_tags[assign_tag_key] == assign_tag_value:
                    freeform_tags_exist = True

            # Del Key
            if cmd.deltag:
                if freeform_tags_exist:
                    freeform_tags.pop(assign_tag_key, None)
                    tags_process = "Deleted"

            # Add Key
            else:
                if not freeform_tags_exist:
                    freeform_tags[assign_tag_key] = assign_tag_value
                    tags_process = "Added"

        # return modified tags
        return defined_tags, freeform_tags, tags_process

    except Exception as e:
        raise RuntimeError("Error in handle_tags: " + str(e.args))


##########################################################################
# Main
##########################################################################
def main():
    cmd = command_line()

    # Identity extract compartments
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
    compartments = []
    tenancy = None
    try:
        print("\nConnecting to Identity Service...")
        identity = oci.identity.IdentityClient(config, signer=signer)
        if cmd.proxy:
            identity.base_client.session.proxies = {'https': cmd.proxy}

        tenancy = identity.get_tenancy(config["tenancy"]).data
        regions = identity.list_region_subscriptions(tenancy.id).data
        compartments = identity_read_compartments(identity, tenancy)

    except Exception as e:
        raise RuntimeError("\nError extracting compartments section - " + str(e))

    ############################################
    # Print Banner
    ############################################
    print_banner(cmd, tenancy)

    ############################################
    # Check if Tag namespace exist
    ############################################
    if cmd.deftag:
        read_tag_namespaces(identity, tenancy)

    ############################################
    # Loop on all regions
    ############################################
    print("\nProcessing Regions...")
    data = []
    warnings = 0
    for region_name in [str(es.region_name) for es in regions]:

        # check if filter by region
        if cmd.region:
            if cmd.region not in region_name:
                continue

        print("\nRegion " + region_name + "...")

        # set the region in the config and signer
        config['region'] = region_name
        signer.region = region_name

        # connect to ComputeClient
        compute_client = oci.core.ComputeClient(config, signer=signer)
        if cmd.proxy:
            compute_client.base_client.session.proxies = {'https': cmd.proxy}

        # connect to BlockstorageClient
        blockstorage_client = oci.core.BlockstorageClient(config, signer=signer)
        if cmd.proxy:
            blockstorage_client.base_client.session.proxies = {'https': cmd.proxy}

        ############################################
        # Loop on all compartments for instances
        ############################################
        try:
            for compartment in compartments:

                print("    Compartment " + str(compartment.name))
                handle_instances(compute_client, compartment, region_name)
                handle_block_volumes(blockstorage_client, compartment, region_name)
                handle_boot_volumes(identity, tenancy.id, blockstorage_client, compartment, region_name)

        except Exception as e:
            raise RuntimeError("\nError extracting Instances - " + str(e))

    ############################################
    # Print Output as JSON
    ############################################
    if cmd.print_report:
        print_header("Output")
        print(json.dumps(data, indent=4, sort_keys=False))

    if warnings > 0:
        print_header(str(warnings) + " Warnings appeared")
    print_header("Completed at " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


############################################
# Execute
############################################
main()
