"""
Monitors and controls the Tesla gateway.
"""
 
# Some manual configuration is required for this script to work, assistance
# to automate these steps would be welcome - config flow & capatcha
# 
# Requires a valid cache.json saved at custom_components/tesla_gateway/cache.json
# cache.json needs to be manually created using teslapy 
# 
# Requires tesla email (used to create cache.json) loaded to configuration.yaml
# 
# configuration.yaml:
# ===================
# tesla_gateway:
#   username = yourtesla@email.com
# 
# Additional logging information can be recorded through configuration.yaml:
# 
# configuration.yaml:
# ===================
# logger:
#   default: warning
#   logs:
#     custom_components.tesla_gateway: debug
#     teslapy: debug

import logging

import asyncio
import voluptuous as vol
import teslapy
import aiohttp
import asyncio
import async_timeout
import base64
import hashlib
import json
import os
import re
import time
from urllib.parse import parse_qs
import voluptuous as vol
from homeassistant import config_entries, core
from homeassistant.const import (
    CONF_USERNAME,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from homeassistant.const import (
    CONF_USERNAME,
    )
import homeassistant.helpers.config_validation as cv

DOMAIN = 'tesla_gateway'

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_USERNAME): cv.string,
    }),
}, extra=vol.ALLOW_EXTRA)


@asyncio.coroutine
def async_setup_entry(
    hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry
) -> bool:
    websession = async_get_clientsession(hass, verify_ssl=False)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][config_entry.entry_id] = config_entry.data
    domain_config = dict(config_entry.data)
    conf_user = domain_config[CONF_USERNAME]
    # setup_common(domain_config=domain_config)
    tesla = teslapy.Tesla(conf_user, cache_file="/config/custom_components/tesla_gateway/cache.json")
    return True

@asyncio.coroutine
def async_setup(hass, config):

    domain_config = config[DOMAIN]
    conf_user = domain_config[CONF_USERNAME]
    
    tesla = teslapy.Tesla(conf_user, cache_file="/config/custom_components/tesla_gateway/cache.json")
    _LOGGER.debug(tesla)


    def get_battery():
        _LOGGER.debug("get_battery()")
        batteries = tesla.battery_list()
        _LOGGER.debug(batteries)
        if len(batteries) > 0:
            return batteries[0]
        else:
            return None
    
    @asyncio.coroutine
    async def set_operation(service):
        
        _LOGGER.debug("set_operation()")
        _LOGGER.debug(service)
        battery = await hass.async_add_executor_job(get_battery)
        if not battery:
            _LOGGER.warning('Battery object is None')
            return None

        await hass.async_add_executor_job(battery.set_operation, service.data['real_mode'])
        if 'backup_reserve_percent' in service.data:
            await hass.async_add_executor_job(battery.set_backup_reserve_percent, service.data['backup_reserve_percent'])

    hass.services.async_register(DOMAIN, 'set_operation', set_operation)

    @asyncio.coroutine
    async def set_reserve(service):
        
        _LOGGER.debug("set_reserve")
        battery = await hass.async_add_executor_job(get_battery)
        if not battery:
            _LOGGER.warning('Battery object is None')
            return None
            
        if 'backup_reserve_percent' in service.data:
            await hass.async_add_executor_job(battery.set_backup_reserve_percent, service.data['backup_reserve_percent'])

    hass.services.async_register(DOMAIN, 'set_reserve', set_reserve)

    return True
