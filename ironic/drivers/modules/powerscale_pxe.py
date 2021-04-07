# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
PowerScale Boot Interface
"""


from futurist import periodics
from ironic_lib import metrics_utils
from oslo_config import cfg
from oslo_log import log as logging

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import pxe_utils
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base
from ironic.drivers.modules import pxe_base
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

METRICS = metrics_utils.get_metrics_logger(__name__)


class PowerScaleBoot(pxe_base.PXEBaseMixin, base.BootInterface):

    capabilities = ['ramdisk_boot', 'pxe_boot']
    ipxe_enabled = True

    @METRICS.timer('PowerScaleBoot.clean_up_ramdisk')
    def clean_up_ramdisk(self, task):
        """Cleans up the boot of ironic ramdisk.

        This method cleans up the PXE environment that was setup for booting
        the deploy or rescue ramdisk. It unlinks the deploy/rescue
        kernel/ramdisk in the node's directory in tftproot and removes it's PXE
        config.

        :param task: a task from TaskManager.
        :param mode: Label indicating a deploy or rescue operation
            was carried out on the node. Supported values are 'deploy' and
            'rescue'. Defaults to 'deploy', indicating deploy operation was
            carried out.
        :returns: None
        """
        node = task.node
        mode = deploy_utils.rescue_or_deploy_mode(node)
        try:
            images_info = pxe_utils.get_image_info(
                node, mode=mode, ipxe_enabled=self.ipxe_enabled)
        except exception.MissingParameterValue as e:
            LOG.warning('Could not get %(mode)s image info '
                        'to clean up images for node %(node)s: %(err)s',
                        {'mode': mode, 'node': node.uuid, 'err': e})
        else:
            pxe_utils.clean_up_pxe_env_powerscale(
                task, images_info, ipxe_enabled=self.ipxe_enabled)

    @METRICS.timer('PowerScaleBoot.prepare_ramdisk')
    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of Ironic ramdisk using PXE.

        This method prepares the boot of the deploy or rescue kernel/ramdisk
        after reading relevant information from the node's driver_info and
        instance_info.

        :param task: a task from TaskManager.
        :param ramdisk_params: the parameters to be passed to the ramdisk.
            pxe driver passes these parameters as kernel command-line
            arguments.
        :returns: None
        :raises: MissingParameterValue, if some information is missing in
            node's driver_info or instance_info.
        :raises: InvalidParameterValue, if some information provided is
            invalid.
        :raises: IronicException, if some power or set boot boot device
            operation failed on the node.
        """
        node = task.node

        # Label indicating a deploy or rescue operation being carried out on
        # the node, 'deploy' or 'rescue'. Unless the node is in a rescue like
        # state, the mode is set to 'deploy', indicating deploy operation is
        # being carried out.
        mode = deploy_utils.rescue_or_deploy_mode(node)

        dhcp_opts = pxe_utils.dhcp_options_for_powerscale(task)
        provider = dhcp_factory.DHCPFactory()
        provider.update_dhcp(task, dhcp_opts)

        pxe_info = pxe_utils.get_image_info(node, mode=mode,
                                            ipxe_enabled=True)

        # NODE: Try to validate and fetch instance images only
        # if we are in DEPLOYING state.
        if node.provision_state == states.DEPLOYING:
            pxe_info.update(
                pxe_utils.get_instance_image_info(
                    task, ipxe_enabled=True))

        boot_mode_utils.sync_boot_mode(task)

        pxe_options = pxe_utils.build_pxe_config_options(
            task, pxe_info, ipxe_enabled=self.ipxe_enabled,
            ramdisk_params=ramdisk_params)
        # TODO(dtantsur): backwards compability hack, remove in the V release
        if ramdisk_params.get("ipa-api-url"):
            pxe_options["ipa-api-url"] = ramdisk_params["ipa-api-url"]

        if self.ipxe_enabled:
            pxe_config_template = deploy_utils.get_ipxe_config_template(node)
        else:
            pxe_config_template = deploy_utils.get_pxe_config_template(node)

        pxe_utils.create_pxe_config(task, pxe_options,
                                    pxe_config_template,
                                    ipxe_enabled=self.ipxe_enabled)
        manager_utils.node_set_boot_device(task, boot_devices.PXE,
                                           persistent=False)

        if self.ipxe_enabled and CONF.pxe.ipxe_use_swift:
            kernel_label = '%s_kernel' % mode
            ramdisk_label = '%s_ramdisk' % mode
            pxe_info.pop(kernel_label, None)
            pxe_info.pop(ramdisk_label, None)

        if pxe_info:
            pxe_utils.cache_ramdisk_powerscale(
                    task, pxe_info,
                    ipxe_enabled=self.ipxe_enabled)

        LOG.debug('Ramdisk (i)PXE boot for node %(node)s has been prepared '
                  'with kernel params %(params)s',
                  {'node': node.uuid, 'params': pxe_options})

    @METRICS.timer('PowerScaleBoot.prepare_instance')
    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance after reading
        relevant information from the node's instance_info. In case of netboot,
        it updates the dhcp entries and switches the PXE config. In case of
        localboot, it cleans up the PXE config.

        :param task: a task from TaskManager.
        :returns: None
        """
        boot_mode_utils.sync_boot_mode(task)
        boot_mode_utils.configure_secure_boot_if_needed(task)

        node = task.node
        # Clean up the deployment configuration
        pxe_utils.clean_up_pxe_config_powerscale(
            task, ipxe_enabled=self.ipxe_enabled)
        boot_device = boot_devices.DISK

        if boot_device and task.node.provision_state != states.ACTIVE:
            manager_utils.node_set_boot_device(task, boot_device,
                                               persistent=True)


    @METRICS.timer('PowerScaleBoot.clean_up_instance')
    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the environment that was setup for booting
        the instance. It unlinks the instance kernel/ramdisk in node's
        directory in tftproot and removes the PXE config.

        :param task: a task from TaskManager.
        :returns: None
        """
        node = task.node

        try:
            images_info = pxe_utils.get_instance_image_info(
                task, ipxe_enabled=self.ipxe_enabled)
        except exception.MissingParameterValue as e:
            LOG.warning('Could not get instance image info '
                        'to clean up images for node %(node)s: %(err)s',
                        {'node': node.uuid, 'err': e})
        else:
            pxe_utils.clean_up_pxe_env_powerscale(task, images_info,
                                       ipxe_enabled=self.ipxe_enabled)

        boot_mode_utils.deconfigure_secure_boot_if_needed(task)
