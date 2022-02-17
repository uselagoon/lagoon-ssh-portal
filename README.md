# Lagoon SSH Portal

[![Release](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml/badge.svg)](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml)
[![Coverage](https://coveralls.io/repos/github/uselagoon/lagoon-ssh-portal/badge.svg?branch=main)](https://coveralls.io/github/uselagoon/lagoon-ssh-portal?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/uselagoon/lagoon-ssh-portal)](https://goreportcard.com/report/github.com/uselagoon/lagoon-ssh-portal)

This is an experimental cluster-local SSH service for [Lagoon](https://github.com/uselagoon/lagoon).

## Architecture

This git repository comprises two services: `service-api`, and `ssh-portal`.
These two services communicate over a backend messaging system.
Currently the message system used is [NATS](https://nats.io/).

### Service API

`service-api` is part of Lagoon Core, and serves requests from other Lagoon components such as the SSH portal, which may be in a remote cluster.

`service-api` is explicitly _not_ a public API and makes no guarantees about compatiblity.
It is _only_ designed to cater to the requirements of other internal Lagoon services.

### SSH Portal

`ssh-portal` is part of Lagoon Remote, and implements an SSH server which connects incoming SSH sessions with pods running in the cluster.
To perform authentication it communicates back to `service-api` running in Lagoon Core, which responds with a true/false if the SSH key is valid for the requested Lagoon environment.

`ssh-portal` implements shell access with service and container selection [as described in the Lagoon documentation](https://docs.lagoon.sh/using-lagoon-advanced/ssh/#ssh-into-a-pod), but it does not implement token generation.

Unlike the existing Lagoon SSH service, `ssh-portal` _only_ provides access to Lagoon environments running in the local cluster.
