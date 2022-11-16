# Lagoon SSH services

[![Release](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml/badge.svg)](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml)
[![Coverage](https://coveralls.io/repos/github/uselagoon/lagoon-ssh-portal/badge.svg?branch=main)](https://coveralls.io/github/uselagoon/lagoon-ssh-portal?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/uselagoon/lagoon-ssh-portal)](https://goreportcard.com/report/github.com/uselagoon/lagoon-ssh-portal)

This repository contains three related SSH services for [Lagoon](https://github.com/uselagoon/lagoon).

## SSH Portal

`ssh-portal` is a cluster-local SSH service which enables SSH access to running workloads in a Lagoon Remote.
To perform authentication it communicates back to `ssh-portal-api` running in Lagoon Core, which responds with a true/false if the SSH key is valid for the requested Lagoon environment.

`ssh-portal` implements shell access with service and container selection [as described in the Lagoon documentation](https://docs.lagoon.sh/using-lagoon-advanced/ssh/#ssh-into-a-pod), but it does not implement token generation.
Unlike the existing Lagoon SSH service, `ssh-portal` _only_ provides access to Lagoon environments running in the local cluster.

## SSH Portal API

`ssh-portal-api` is part of Lagoon Core, and serves authentication and authorization queries from `ssh-portal` services running in a Lagoon Remote.

`ssh-portal-api` is explicitly _not_ a public API and makes no guarantees about compatibility.
It is _only_ designed to cater to the requirements of `ssh-portal`.

## SSH Token

`ssh-token` is part of Lagoon Core, and it serves JWT token generation requests.

This service does not provide shell access.
Instead, it authenticates users by SSH key and returns a user access token which can then be used to authenticate to the Lagoon API.

## Administration and Troubleshooting

If a user gets an error from a Lagoon SSH service it may not contain much detail for security reasons.
However it _will_ contain a Session ID (SID) which is logged alongside any other log messages produced by the SSH services.
This helps to correlate error messages in service logs to reported user connection errors.
