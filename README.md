# prom-grafana-lbac

A label-based access control proxy to enable multi-tenant read access in Prometheus by enforcing label restrictions based on [Grafana teams](https://grafana.com/docs/grafana/latest/administration/team-management/) membership.

prom-grafana-lbac enforces a given label in a given PromQL query, in Prometheus API responses or in Alertmanager API requests coming from a Grafana instance based on the teams the requestor is a member of. This enables read multi-tenancy for observability platforms using Prometheus (or Prometheus-compatible backends, such as Thanos and Mimir) as a Grafana datasource purely through Grafana teams.

This project is heavily inspired by [prom-label-proxy](https://github.com/prometheus-community/prom-label-proxy) and uses the same CLI argments. 

## How it works

Grafana sends an X-Grafana-Id header when it proxies datasources. This header is a signed JWT with the user and org that the request was made from. We can validate and verify the token using Grafana's public JWKS exposed on `/api/signing-keys/keys`.

Once the user is verified, we call Grafana to fetch the list of teams that the user is a member of. The [User API](https://grafana.com/docs/grafana/latest/developers/http_api/user/) requires authenticating using basic auth with a Grafana admin's credentials.

The names of teams that the requestor is part of are then used as the label values enforced in the query, using [prom-label-proxy](https://github.com/prometheus-community/prom-label-proxy).

## Installation

- **Docker**: images are published at `ghcr.io/amoolaa/prom-grafana-lbac:latest`
- **Binary**: download a precompiled binary from the [Releases](https://github.com/amoolaa/prom-grafana-lbac/releases) page
- or clone and build from source

## Motivation

I help run an LGTM stack using [Grafana Orgs](https://grafana.com/docs/grafana/latest/administration/organization-management/) to handle tenancy. This works alright for small tenants, but as they grow larger tenants need fine-grained RBAC on their datasources. This project provides a way to provide additional label-based-access controls (LBAC) on their Prometheus-compatible datasources in addition to the other RBAC features in Grafana Teams. This is also a way to restrict read access in a single org, multi-team setup in Grafana OSS similar to LBAC offerings in Grafana Enterprise and Cloud.