# Tesla Powerwall Gateway for Home Assistant

Uses the Tesla API to control a Powerwall.

## Installation

Install the repository through HACS by adding a custom repository or by manually copying the `custom_components/tesla_gateway` folder into your `custom_components` folder.

## Configuration

The component is now configured through the user interface.

To setup the integration, got to Configuration -> Integrations, and search for Tesla Gateway
Add your Tesla username and password.

## Services

The integration provides two services - `set_operation` and `set_reserve`.
You can call these from the Developer -> Services page, or include them in automations.

### set_operation

Sets the operation mode of the PowerWall. Possible values include `self_consumption`, `backup` or `autonomous`.
Service data looks like this:

```
real_mode: 'self_consumption'
backup_reserve_percent: 20
```

### set_reserve

Changes battery reserve percent.

```
backup_reserve_percent: 10
```
