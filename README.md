# Lagoon SSH services

[![Go Reference](https://pkg.go.dev/badge/github.com/uselagoon/lagoon-ssh-portal.svg)](https://pkg.go.dev/github.com/uselagoon/lagoon-ssh-portal)
[![Release](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml/badge.svg)](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/release.yaml)
[![coverage](https://raw.githubusercontent.com/uselagoon/lagoon-ssh-portal/badges/.badges/main/coverage.svg)](https://github.com/uselagoon/lagoon-ssh-portal/actions/workflows/coverage.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/uselagoon/lagoon-ssh-portal)](https://goreportcard.com/report/github.com/uselagoon/lagoon-ssh-portal)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/uselagoon/lagoon-ssh-portal/badge)](https://securityscorecards.dev/viewer/?uri=github.com/uselagoon/lagoon-ssh-portal)

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

## High-level Architecture

This diagram shows the architecture of the Lagoon SSH services.
It depicts two Lagoon Remote clusters, each with an `ssh-portal` installed, and a controlling Lagoon Core cluster with the `ssh-portal-api` installed.

Some important features (which differ from the legacy Lagoon SSH service):

* There are multiple SSH endpoints.
  Each Kubernetes Cluster running Lagoon environments (i.e. `lagoon-remote` cluster) has its own `ssh-portal`.
* In order to SSH to a Lagoon environment, the user has to initiate a connection to the `ssh-portal` running in the same `lagoon-remote` cluster.
* In order to retrieve a Lagoon API token, the user has to connect to the `ssh-token` endpoint in the `lagoon-core` cluster.
* Inter-process communication between Lagoon SSH components is handled by [NATS](https://nats.io/).
  A single NATS cluster is formed between NATS nodes running in remote and core Kubernetes clusters.
* Communication between NATS leaf nodes in remote clusters and NATS in the core cluster is protected via mutual TLS.

```mermaid
flowchart
    subgraph lagoon-remote1
    sp1[ssh-portal]
    natsRemote1[NATS Leaf]
    sp1 --- natsRemote1
    end
    subgraph lagoon-remote2
    sp2[ssh-portal]
    natsRemote2[NATS Leaf]
    sp2 --- natsRemote2
    end
    subgraph lagoon-core
    spa[ssh-portal-api]
    natsCore[NATS]
    lagoon[Lagoon API-DB / Keycloak]
    st[ssh-token]
    spa --- natsCore
    spa --- lagoon
    st --- lagoon
    end
    sshShell1(SSH shell requests for lagoon-remote1)
    sshShell2(SSH shell requests for lagoon-remote2)
    sshToken(SSH token requests)
    sshToken --> |SSH| st
    sshShell1 --> |SSH| sp1
    sshShell2 --> |SSH| sp2
    natsRemote1 --- |mTLS| natsCore
    natsRemote2 --- |mTLS| natsCore
```

### SSH Portal sequence diagram

This diagram shows the sequence of a successful SSH shell connection to a Lagoon service in a Kubernetes cluster.

```mermaid
sequenceDiagram
    actor SSH client
    box lagoon-remote
    participant ssh-portal
    participant Kubernetes API
    end
    box lagoon-core
    participant ssh-portal-api
    end
    SSH client->>+ssh-portal: ssh project-env@ssh.lagoon.example.com
    ssh-portal->>+ssh-portal-api: Can this SSH key access this environment?
    ssh-portal-api->>-ssh-portal: Yes, this user (via SSH key lookup) can access this environment.
    ssh-portal-->>Kubernetes API: Execute shell command in target container.
    ssh-portal->>-SSH client: Return control to SSH client.
```

### SSH Token sequence diagram

This diagram shows the sequence of a successful SSH token request.

```mermaid
sequenceDiagram
    actor SSH client
    box lagoon-core
    participant ssh-token
    end
    SSH client->>+ssh-token: ssh lagoon@token.lagoon.example.com
    ssh-token->>-SSH client: Return token to SSH client.
```

## Troubleshooting SSH connections

If you are running into issues with SSH in Lagoon, the first thing to check is if the user is connecting to the correct SSH endpoint:

* If they want to execute a command or get an interactive shell, they need to connect to the `ssh-portal` endpoint of the cluster their Lagoon environment is running in.
  This information can be retrieved from the Lagoon API.
* If they want to get a Lagoon API token, they need to connect to the single `ssh-token` endpoint.
  This endpoint does not provide any shell access; it only provisions API tokens.

The [Lagoon CLI](https://github.com/uselagoon/lagoon-cli)'s `ssh` command will take care of all this transparently, and is highly recommended.

If a user gets an error from a Lagoon SSH service it may not contain much detail for security reasons.
However, errors returned to the user will contain a unique Session ID (SID).
This SID is also logged to the standard error of the SSH service along with any errors, so it will appear in the container logs along with more detail about exactly what went wrong.
This helps to correlate error messages reported by users with detailed errors in service logs visible only to administrators.
