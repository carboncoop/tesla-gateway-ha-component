# Tesla Powerwall Gateway for Home Assistant

Uses the Tesla API to control a Powerwall.

## Installation

Install the repository through HACS or by copying the `custom_components/tesla_gateway` folder into your `custom_components` folder.

## Configuration

The component is currently configured throuhg YAML. Work on a config flow version of it is in progress.

To setup the integration, add the following to your `configuration.yaml` file:

```
tesla_gateway:
  username: <your tesla username>
  password: <your tesla password>
```

## Services

The integration provides two services - `set_operation` and `set_reserve`.
You can call these from the Developer -> Services page, or include them in automations.

### set_operation

Sets the operation mode of the PowerWall. Possible values include `self_consumption`, `backup` or `autonomous`.
Service data looks like this:

```
real_mode: 'self_consumption'
```

### set_reserve

Changes battery reserve percent in `self_consumption` mode.

```
reserve_percent: 10
```
